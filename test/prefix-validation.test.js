'use strict';

// Locks the prefix rules shared by frontend/app.js, api-server.js, and
// haraka/plugins/save_email.js. If this regex changes in the sources, this
// test must change with it, in all places at once.

const { test } = require('node:test');
const assert = require('node:assert');

const PREFIX_RE = /^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,48}[a-zA-Z0-9])?$/;

function validPrefix(prefix) {
    return PREFIX_RE.test(prefix) && !prefix.includes('..');
}

test('accepts common prefixes', () => {
    for (const prefix of ['a', 'my-email', 'a1.b2', 'midnight-fox42', 'A_b-c.d9']) {
        assert.equal(validPrefix(prefix), true, prefix);
    }
});

test('accepts a 50-char prefix and rejects 51', () => {
    assert.equal(validPrefix('a'.repeat(50)), true);
    assert.equal(validPrefix('a'.repeat(51)), false);
});

test('rejects malformed prefixes', () => {
    for (const prefix of ['', '.a', 'a.', '-a', 'a-', '_a', 'a..b', 'a b', 'a@b', 'ü', 'a/../b']) {
        assert.equal(validPrefix(prefix), false, JSON.stringify(prefix));
    }
});

test('regex in this test matches the one in the sources', () => {
    const fs = require('fs');
    const path = require('path');
    // The prefix core appears standalone in app.js and as the local part of
    // the full email regex in the API server and the Haraka plugin.
    const core = '^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,48}[a-zA-Z0-9])?';
    assert.ok(String(PREFIX_RE).includes(core));
    for (const file of ['frontend/app.js', 'api-server.js', 'haraka/plugins/save_email.js']) {
        const content = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        assert.ok(content.includes(core), `${file} no longer contains the locked prefix regex`);
    }
});
