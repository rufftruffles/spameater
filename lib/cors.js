'use strict';

// Decide the Access-Control-Allow-Origin value. Exact-host checks only:
// a prefix test (e.g. startsWith('https://localhost')) would match
// look-alikes such as localhost.evil.com. Shared by api-server.js and the
// test so they can never drift.
function allowedOrigin(origin, host) {
    let allowed = host ? `https://${host}` : '';
    if (origin) {
        let hostname = null;
        try {
            hostname = new URL(origin).hostname;
        } catch (err) {
            hostname = null;
        }
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            allowed = origin; // dev only, exact host match
        } else if (origin === `https://${host}`) {
            allowed = origin; // same origin in production
        }
    }
    return allowed;
}

module.exports = { allowedOrigin };
