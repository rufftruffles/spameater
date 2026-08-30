'use strict';

// Locks the CORS allow-origin decision (SEC-1) against the real code in
// lib/cors.js, so a regression to a prefix match fails here.

const { test } = require('node:test');
const assert = require('node:assert');
const { allowedOrigin } = require('../lib/cors.js');

test('same-origin is echoed', () => {
    assert.equal(allowedOrigin('https://mail.example.com', 'mail.example.com'), 'https://mail.example.com');
});

test('localhost origins allowed exactly', () => {
    assert.equal(allowedOrigin('http://localhost:8080', 'mail.example.com'), 'http://localhost:8080');
    assert.equal(allowedOrigin('http://127.0.0.1:8080', 'mail.example.com'), 'http://127.0.0.1:8080');
});

test('localhost look-alikes are NOT allowed', () => {
    for (const evil of [
        'https://localhost.evil.com',
        'http://localhost.evil.com',
        'https://localhostx.com',
        'https://notlocalhost',
        'https://127.0.0.1.evil.com'
    ]) {
        assert.equal(allowedOrigin(evil, 'mail.example.com'), 'https://mail.example.com', evil);
    }
});

test('unrelated origin falls back to same-origin', () => {
    assert.equal(allowedOrigin('https://evil.com', 'mail.example.com'), 'https://mail.example.com');
});

test('garbage origin does not throw', () => {
    assert.equal(allowedOrigin('not a url', 'mail.example.com'), 'https://mail.example.com');
});

test('no origin header returns same-origin', () => {
    assert.equal(allowedOrigin(undefined, 'mail.example.com'), 'https://mail.example.com');
    assert.equal(allowedOrigin('', ''), '');
});
