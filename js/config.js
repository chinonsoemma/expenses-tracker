/* =========================================
   EXPENSE TRACKER - APP CONFIGURATION
   File: js/config.js

   Public values only. Never put secrets here
   (no client secret, no access keys, no passwords).
   Everything in this file is visible to anyone
   who opens the site in a browser.
========================================= */

window.APP_CONFIG = {
    // AWS / Cognito
    AWS_REGION: "eu-west-2",
    USER_POOL_ID: "eu-west-2_XXXXXXXXX",          // Cognito > User pool overview
    CLIENT_ID: "YOUR_APP_CLIENT_ID",              // App client (no client secret)

    // Hosted UI domain, from Cognito > App integration > Domain
    COGNITO_DOMAIN: "https://YOUR_DOMAIN_PREFIX.auth.eu-west-2.amazoncognito.com",

    // Must match the "Allowed callback URL" in Cognito exactly
    REDIRECT_URI: new URL("login.html", window.location.href).href,

    // Must match the "Allowed sign-out URL" in Cognito exactly
    LOGOUT_URI: new URL("index.html", window.location.href).href,

    SCOPES: "openid email profile",

    // Backend API (used by api.js)
    API_BASE_URL: "https://YOUR_API_ID.execute-api.eu-west-2.amazonaws.com"
};