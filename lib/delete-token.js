'use strict';

// Delete-token HMAC logic shared by the API server and tests.
// Wire format: first 16 hex chars of HMAC-SHA256(secret, "prefix:emailId:window"),
// where window is a 5-minute bucket. Verification accepts the current and the
// previous window to tolerate clock skew.

const crypto = require('crypto');

const TOKEN_WINDOW_MS = 5 * 60 * 1000;
const TOKEN_LENGTH = 16;
const TOKEN_RE = /^[0-9a-f]{16}$/;

function generateDeleteToken(secret, prefix, emailId, windowOffset = 0) {
    const window = Math.floor(Date.now() / TOKEN_WINDOW_MS) + windowOffset;
    return crypto.createHmac('sha256', secret)
        .update(`${prefix}:${emailId}:${window}`)
        .digest('hex')
        .substring(0, TOKEN_LENGTH);
}

function verifyDeleteToken(secret, prefix, emailId, token) {
    // Length/format guard: timingSafeEqual throws on length mismatch, and the
    // header value is attacker-controlled.
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
        return false;
    }
    const candidate = Buffer.from(token);
    for (const offset of [0, -1]) {
        const expected = Buffer.from(generateDeleteToken(secret, prefix, emailId, offset));
        if (crypto.timingSafeEqual(candidate, expected)) {
            return true;
        }
    }
    return false;
}

module.exports = { generateDeleteToken, verifyDeleteToken, TOKEN_WINDOW_MS };
