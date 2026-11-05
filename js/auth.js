/* =========================================
   EXPENSE TRACKER - AUTH (COGNITO HOSTED UI)
   File: js/auth.js

   Flow: Authorization Code + PKCE (no client secret)
     1. redirectToLogin()  -> Cognito Hosted UI
     2. Cognito sends the user back to REDIRECT_URI?code=...
     3. handleCallback()   -> exchanges the code for tokens
     4. Tokens are stored; the guard protects private pages
     5. logoutUser()       -> clears tokens, ends the Cognito session

   Reads from js/config.js (window.APP_CONFIG):
     COGNITO_DOMAIN, CLIENT_ID, REDIRECT_URI, LOGOUT_URI, SCOPES

   Public API (window.Auth):
     Auth.redirectToLogin()
     Auth.redirectToSignup()
     Auth.handleCallback()     -> Promise<boolean>
     Auth.requireAuth()        -> Promise<boolean>
     Auth.logoutUser()
     Auth.getIdToken()         -> Promise<string|null>   (use in api.js)
     Auth.getAccessToken()     -> Promise<string|null>
     Auth.getCurrentUser()     -> { email, name, sub } | null
     Auth.isAuthenticated()    -> boolean
     Auth.isConfigured()       -> boolean

   Protected pages are guarded automatically. Just load
   config.js then auth.js on them.
========================================= */

(function () {
    "use strict";

    var config = window.APP_CONFIG || {};

    var PAGES = {
        HOME: "index.html",
        LOGIN: "login.html",
        DASHBOARD: "dashboard.html"
    };

    var PROTECTED_PAGES = [
        "dashboard.html",
        "expenses.html",
        "add-expense.html",
        "categories.html"
    ];

    var PREFIX = "expenseTracker_";
    var KEYS = {
        idToken: PREFIX + "idToken",
        accessToken: PREFIX + "accessToken",
        refreshToken: PREFIX + "refreshToken",
        expiresAt: PREFIX + "expiresAt",
        verifier: PREFIX + "pkceVerifier",
        state: PREFIX + "oauthState",
        returnTo: PREFIX + "returnTo"
    };

    var refreshPromise = null;


    /* =========================================
       1. CONFIG HELPERS
    ========================================= */

    function domainUrl() {
        var domain = String(config.COGNITO_DOMAIN || "").replace(/\/+$/, "");
        if (domain && !/^https?:\/\//i.test(domain)) {
            domain = "https://" + domain;
        }
        return domain;
    }

    function isConfigured() {
        var domain = String(config.COGNITO_DOMAIN || "");
        var clientId = String(config.CLIENT_ID || "");
        return Boolean(
            domain && clientId &&
            domain.indexOf("YOUR_") === -1 &&
            clientId.indexOf("YOUR_") === -1
        );
    }

    function assertConfigured() {
        if (!isConfigured()) {
            throw new Error("Cognito is not configured. Update js/config.js.");
        }
    }

    function currentPageName() {
        return window.location.pathname.split("/").pop() || PAGES.HOME;
    }


    /* =========================================
       2. PKCE HELPERS
    ========================================= */

    function base64Url(bytes) {
        var binary = "";
        bytes.forEach(function (b) { binary += String.fromCharCode(b); });
        return btoa(binary)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    }

    function randomString(byteLength) {
        var bytes = new Uint8Array(byteLength);
        crypto.getRandomValues(bytes);
        return base64Url(bytes);
    }

    async function sha256(text) {
        var data = new TextEncoder().encode(text);
        var digest = await crypto.subtle.digest("SHA-256", data);
        return new Uint8Array(digest);
    }


    /* =========================================
       3. TOKEN STORAGE
    ========================================= */

    function storeTokens(tokens) {
        var expiresIn = Number(tokens.expires_in) || 3600;

        localStorage.setItem(KEYS.idToken, tokens.id_token);
        localStorage.setItem(KEYS.accessToken, tokens.access_token);
        localStorage.setItem(KEYS.expiresAt, String(Date.now() + expiresIn * 1000));

        // A refresh response does not include a new refresh token
        if (tokens.refresh_token) {
            localStorage.setItem(KEYS.refreshToken, tokens.refresh_token);
        }
    }

    function clearTokens() {
        [KEYS.idToken, KEYS.accessToken, KEYS.refreshToken, KEYS.expiresAt]
            .forEach(function (key) { localStorage.removeItem(key); });
    }

    function parseJwt(token) {
        try {
            var payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
            var json = decodeURIComponent(
                atob(payload).split("").map(function (c) {
                    return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
                }).join("")
            );
            return JSON.parse(json);
        } catch (error) {
            return null;
        }
    }


    /* =========================================
       4. REDIRECT TO HOSTED UI
    ========================================= */

    async function startAuthFlow(path) {
        assertConfigured();

        var verifier = randomString(64);
        var challenge = base64Url(await sha256(verifier));
        var state = randomString(16);

        sessionStorage.setItem(KEYS.verifier, verifier);
        sessionStorage.setItem(KEYS.state, state);

        var params = new URLSearchParams({
            response_type: "code",
            client_id: config.CLIENT_ID,
            redirect_uri: config.REDIRECT_URI,
            scope: config.SCOPES || "openid email profile",
            state: state,
            code_challenge: challenge,
            code_challenge_method: "S256"
        });

        window.location.href = domainUrl() + path + "?" + params.toString();
    }

    function redirectToLogin() {
        return startAuthFlow("/oauth2/authorize");
    }

    function redirectToSignup() {
        return startAuthFlow("/signup");
    }


    /* =========================================
       5. TOKEN ENDPOINT
    ========================================= */

    async function requestTokens(fields) {
        var response;
        try {
            response = await fetch(domainUrl() + "/oauth2/token", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams(fields).toString()
            });
        } catch (error) {
            throw new Error("Could not reach the sign-in service. Check your connection.");
        }

        var data = {};
        try { data = await response.json(); } catch (error) { data = {}; }

        if (!response.ok) {
            var failure = new Error(data.error_description || data.error || "Sign-in failed.");
            failure.code = data.error || "token_error";
            throw failure;
        }
        return data;
    }


    /* =========================================
       6. CALLBACK HANDLER
       Call on the page Cognito redirects to (login.html).
       Resolves true if a sign-in was completed, false if
       there was no ?code in the URL. Throws on failure.
    ========================================= */

    function cleanUrl() {
        window.history.replaceState({}, document.title, window.location.pathname);
    }

    function safeReturnPath(path) {
        // Only simple page names, never external URLs
        return /^[\w\-\/]+\.html$/.test(path || "") ? path : PAGES.DASHBOARD;
    }

    async function handleCallback() {
        var params = new URLSearchParams(window.location.search);

        var oauthError = params.get("error");
        if (oauthError) {
            var description = params.get("error_description") || oauthError;
            cleanUrl();
            throw new Error(description);
        }

        var code = params.get("code");
        if (!code) { return false; }

        var state = params.get("state");
        var expectedState = sessionStorage.getItem(KEYS.state);
        var verifier = sessionStorage.getItem(KEYS.verifier);

        sessionStorage.removeItem(KEYS.state);
        sessionStorage.removeItem(KEYS.verifier);
        cleanUrl();

        if (!state || state !== expectedState || !verifier) {
            throw new Error("Your sign-in could not be verified. Please try again.");
        }

        assertConfigured();

        var tokens = await requestTokens({
            grant_type: "authorization_code",
            client_id: config.CLIENT_ID,
            code: code,
            redirect_uri: config.REDIRECT_URI,
            code_verifier: verifier
        });

        storeTokens(tokens);

        var returnTo = safeReturnPath(sessionStorage.getItem(KEYS.returnTo));
        sessionStorage.removeItem(KEYS.returnTo);
        window.location.replace(returnTo);
        return true;
    }


    /* =========================================
       7. SESSION HELPERS
    ========================================= */

    function tokenIsFresh() {
        var expiresAt = Number(localStorage.getItem(KEYS.expiresAt) || 0);
        // 60 second buffer so requests do not fail mid-flight
        return Boolean(localStorage.getItem(KEYS.idToken)) &&
               Date.now() < expiresAt - 60000;
    }

    function isAuthenticated() {
        return tokenIsFresh() || Boolean(localStorage.getItem(KEYS.refreshToken));
    }

    async function refreshSession() {
        var refreshToken = localStorage.getItem(KEYS.refreshToken);
        if (!refreshToken || !isConfigured()) { return false; }

        // Share one refresh between simultaneous callers
        if (!refreshPromise) {
            refreshPromise = requestTokens({
                grant_type: "refresh_token",
                client_id: config.CLIENT_ID,
                refresh_token: refreshToken
            }).then(function (tokens) {
                storeTokens(tokens);
                return true;
            }).catch(function (error) {
                // Refresh token rejected: the session is over
                if (error.code === "invalid_grant") { clearTokens(); }
                return false;
            }).finally(function () {
                refreshPromise = null;
            });
        }
        return refreshPromise;
    }

    async function getIdToken() {
        if (tokenIsFresh()) { return localStorage.getItem(KEYS.idToken); }
        var refreshed = await refreshSession();
        return refreshed ? localStorage.getItem(KEYS.idToken) : null;
    }

    async function getAccessToken() {
        if (tokenIsFresh()) { return localStorage.getItem(KEYS.accessToken); }
        var refreshed = await refreshSession();
        return refreshed ? localStorage.getItem(KEYS.accessToken) : null;
    }

    function getCurrentUser() {
        var token = localStorage.getItem(KEYS.idToken);
        var claims = token ? parseJwt(token) : null;
        if (!claims) { return null; }
        return {
            email: claims.email || "",
            name: claims.name || "",
            sub: claims.sub || ""
        };
    }


    /* =========================================
       8. ROUTE GUARD
    ========================================= */

    // Sends logged-out users to login.html and remembers where they were
    async function requireAuth() {
        var token = await getIdToken();

        if (!token) {
            sessionStorage.setItem(KEYS.returnTo, currentPageName());
            window.location.replace(PAGES.LOGIN);
            return false;
        }

        document.documentElement.style.visibility = "";
        return true;
    }

    // Runs automatically on every page listed in PROTECTED_PAGES
    function runGuard() {
        if (PROTECTED_PAGES.indexOf(currentPageName()) === -1) { return; }

        // Hide the page until we know the user is signed in
        document.documentElement.style.visibility = "hidden";
        requireAuth();
    }


    /* =========================================
       9. LOGOUT
    ========================================= */

    function logoutUser() {
        clearTokens();
        sessionStorage.removeItem(KEYS.returnTo);

        // Not configured: just go back to the login page
        if (!isConfigured()) {
            window.location.replace(PAGES.LOGIN);
            return;
        }

        // Ends the Cognito Hosted UI session too, so the next
        // login asks for credentials again
        var params = new URLSearchParams({
            client_id: config.CLIENT_ID,
            logout_uri: config.LOGOUT_URI
        });
        window.location.href = domainUrl() + "/logout?" + params.toString();
    }


    /* =========================================
       10. START-UP AND PUBLIC API
    ========================================= */

    runGuard();

    // Pages restored from the back/forward cache re-check access
    window.addEventListener("pageshow", function (event) {
        if (event.persisted) { runGuard(); }
    });

    window.Auth = {
        redirectToLogin: redirectToLogin,
        redirectToSignup: redirectToSignup,
        handleCallback: handleCallback,
        requireAuth: requireAuth,
        logoutUser: logoutUser,
        signOut: logoutUser,            // alias for older code
        getIdToken: getIdToken,
        getAccessToken: getAccessToken,
        getCurrentUser: getCurrentUser,
        isAuthenticated: isAuthenticated,
        isConfigured: isConfigured,
        pages: PAGES
    };

    // Lets a button call logoutUser() directly
    window.logoutUser = logoutUser;
})();