/* =========================================
   EXPENSE TRACKER - CONFIG TEMPLATE
   File: js/config.example.js

   This file is committed. The real js/config.js is NOT.
   To set up locally:  cp js/config.example.js js/config.js
   then replace every REPLACE_ME with your real value.

   Public values only. Never put secrets here
   (no client secret, no access keys, no passwords).
========================================= */

window.APP_CONFIG = {
    // AWS / Cognito
    AWS_REGION: "eu-west-2",
    USER_POOL_ID: "REPLACE_ME",        // e.g. eu-west-2_AbCdEfGhI
    CLIENT_ID: "REPLACE_ME",           // App client (no client secret)

    // Hosted UI domain, e.g. https://your-prefix.auth.eu-west-2.amazoncognito.com
    COGNITO_DOMAIN: "REPLACE_ME",

    // Full URLs registered in the Cognito app client, e.g.
    // http://127.0.0.1:5500/login.html  and  http://127.0.0.1:5500/index.html
    REDIRECT_URI: "REPLACE_ME",
    LOGOUT_URI: "REPLACE_ME",

    SCOPES: "openid email profile",

    // Backend API base URL, e.g. https://abc123.execute-api.eu-west-2.amazonaws.com
    API_BASE_URL: "REPLACE_ME"
};