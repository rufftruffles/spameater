'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { generateDeleteToken, verifyDeleteToken } = require('../lib/delete-token.js');

const SECRET = 'x'.repeat(32);

test('token is 16 lowercase hex chars', () => {
    const token = generateDeleteToken(SECRET, 'foo', 'id1');
    assert.match(token, /^[0-9a-f]{16}$/);
});

test('current window token verifies', () => {
    const token = generateDeleteToken(SECRET, 'foo', 'id1');
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', token), true);
});

test('previous window token verifies (clock skew)', () => {
    const token = generateDeleteToken(SECRET, 'foo', 'id1', -1);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', token), true);
});

test('token from two windows back fails', () => {
    const token = generateDeleteToken(SECRET, 'foo', 'id1', -2);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', token), false);
});

test('token bound to prefix and email id', () => {
    const token = generateDeleteToken(SECRET, 'foo', 'id1');
    assert.equal(verifyDeleteToken(SECRET, 'bar', 'id1', token), false);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id2', token), false);
});

test('wrong-length or malformed token returns false, never throws', () => {
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', 'ab'), false);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', ''), false);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', 'z'.repeat(16)), false);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', 'a'.repeat(64)), false);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', null), false);
    assert.equal(verifyDeleteToken(SECRET, 'foo', 'id1', undefined), false);
});
