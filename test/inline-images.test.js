'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

// The plugin loads DOMPurify and requires ENCRYPTION_KEY at module level
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'x'.repeat(32);
const plugin = require('../haraka/plugins/save_email.js');
const embed = plugin._embedInlineImages;

const IMAGES = {
    'logo@example': { contentType: 'image/png', base64: 'AAAA' }
};

test('replaces double-quoted cid reference', () => {
    const out = embed('<img src="cid:logo@example" alt="logo">', IMAGES);
    assert.equal(out, '<img src="data:image/png;base64,AAAA" alt="logo">');
});

test('replaces single-quoted and case-mismatched cid', () => {
    const out = embed("<img src='cid:LOGO@EXAMPLE'>", IMAGES);
    assert.ok(out.includes('data:image/png;base64,AAAA'));
});

test('leaves unknown cid references alone', () => {
    const html = '<img src="cid:other@example">';
    assert.equal(embed(html, IMAGES), html);
});

test('no-op without images or html', () => {
    assert.equal(embed('', IMAGES), '');
    const html = '<p>hi</p>';
    assert.equal(embed(html, {}), html);
    assert.equal(embed(html, undefined), html);
});

test('css url(cid:...) form is replaced too', () => {
    const out = embed('<td style="background: url(cid:logo@example)">x</td>', IMAGES);
    assert.ok(out.includes('url(data:image/png;base64,AAAA'));
});
