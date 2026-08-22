'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const R = require('../frontend/email-remap.js');

test('parses 3- and 6-digit hex', () => {
    assert.equal(R.parseColor('#fff').l, 1);
    assert.equal(R.parseColor('#000').l, 0);
    const c = R.parseColor('#ff0000');
    assert.equal(c.h, 0);
    assert.equal(c.s, 1);
    assert.equal(c.a, 1);
});

test('parses 8-digit hex with alpha', () => {
    const c = R.parseColor('#ff000080');
    assert.ok(Math.abs(c.a - 0.5) < 0.01);
});

test('parses rgb and rgba', () => {
    assert.equal(R.parseColor('rgb(255, 0, 0)').h, 0);
    assert.equal(R.parseColor('rgba(0, 0, 255, 0.4)').a, 0.4);
    const g = R.parseColor('rgb(0, 128, 0)');
    assert.ok(g.h > 115 && g.h < 125);
});

test('parses hsl and hsla', () => {
    const c = R.parseColor('hsl(200, 50%, 40%)');
    assert.equal(c.h, 200);
    assert.equal(c.s, 0.5);
    assert.equal(c.l, 0.4);
    assert.equal(R.parseColor('hsla(200, 50%, 40%, 0.7)').a, 0.7);
});

test('parses named colors', () => {
    assert.equal(R.parseColor('white').l, 1);
    assert.equal(R.parseColor('black').l, 0);
    assert.equal(R.parseColor('RED').h, 0);
    assert.ok(R.parseColor('rebeccapurple'));
});

test('returns null for junk and non-colors', () => {
    assert.equal(R.parseColor('bogus(1)'), null);
    assert.equal(R.parseColor('inherit'), null);
    assert.equal(R.parseColor('transparent'), null);
    assert.equal(R.parseColor(''), null);
    assert.equal(R.parseColor('url(http://x/y.png)'), null);
});

test('formatColor round-trips through parseColor', () => {
    const c = R.parseColor('#e8f0fe');
    const again = R.parseColor(R.formatColor(c));
    assert.ok(Math.abs(again.l - c.l) < 0.01);
    assert.ok(Math.abs(again.h - c.h) < 1);
});

test('light background goes dark, hue preserved', () => {
    const input = R.parseColor('#e8f0fe');
    const out = R.remapColor(input, 'background');
    assert.ok(out.l < 0.2, `expected dark, got l=${out.l}`);
    assert.ok(Math.abs(out.h - input.h) < 1);
});

test('white background lands near the app surface tone', () => {
    const out = R.remapColor(R.parseColor('#ffffff'), 'background');
    assert.ok(out.l >= 0.04 && out.l <= 0.1, `l=${out.l}`);
});

test('already-dark background barely moves', () => {
    const input = R.parseColor('#101418');
    const out = R.remapColor(input, 'background');
    assert.ok(Math.abs(out.l - input.l) < 0.08);
});

test('dark text goes light', () => {
    const out = R.remapColor(R.parseColor('#222222'), 'text');
    assert.ok(out.l > 0.75, `l=${out.l}`);
});

test('light text stays light', () => {
    const input = R.parseColor('#f0f0f0');
    const out = R.remapColor(input, 'text');
    assert.ok(out.l >= 0.75);
});

test('mid-tone colors keep their contrast ordering', () => {
    const lighter = R.remapColor(R.parseColor('#dddddd'), 'background');
    const darker = R.remapColor(R.parseColor('#aaaaaa'), 'background');
    assert.ok(lighter.l < darker.l, 'lighter input should map darker than darker input');
});

test('saturation capped after remap', () => {
    const out = R.remapColor(R.parseColor('hsl(340, 100%, 95%)'), 'background');
    assert.ok(out.s <= 0.85);
});

test('alpha preserved by remap', () => {
    const out = R.remapColor(R.parseColor('rgba(255, 255, 255, 0.5)'), 'background');
    assert.equal(out.a, 0.5);
});

test('formatHexColor round-trips', () => {
    assert.equal(R.formatHexColor(R.parseColor('#ffffff')), '#ffffff');
    assert.equal(R.formatHexColor(R.parseColor('#000000')), '#000000');
    const back = R.parseColor(R.formatHexColor(R.parseColor('#cc0000')));
    assert.ok(Math.abs(back.l - R.parseColor('#cc0000').l) < 0.01);
    assert.ok(Math.abs(back.h - 0) < 1);
});

test('remapped black as attribute hex is light', () => {
    const out = R.formatHexColor(R.remapColor(R.parseColor('#000000'), 'text'));
    assert.ok(R.parseColor(out).l > 0.9, out);
});

test('isDarkColor threshold', () => {
    assert.equal(R.isDarkColor(R.parseColor('#111')), true);
    assert.equal(R.isDarkColor(R.parseColor('#eee')), false);
});
