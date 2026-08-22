'use strict';

// SpamEater email color remap engine.
// Pure color math only: no DOM access, so the same file loads in the browser
// (window.EmailRemap) and under node:test (module.exports).
//
// Colors are {h: 0-360, s: 0-1, l: 0-1, a: 0-1}. remapColor() moves light
// backgrounds into a dark band and dark text into a light band while keeping
// hue and alpha, so an email's own contrast relationships survive on the
// app's dark surface. Values that cannot be parsed are left untouched by the
// caller (parseColor returns null).

(function () {

const NAMED_COLORS = {
    aliceblue: 'f0f8ff', antiquewhite: 'faebd7', aqua: '00ffff', aquamarine: '7fffd4',
    azure: 'f0ffff', beige: 'f5f5dc', bisque: 'ffe4c4', black: '000000',
    blanchedalmond: 'ffebcd', blue: '0000ff', blueviolet: '8a2be2', brown: 'a52a2a',
    burlywood: 'deb887', cadetblue: '5f9ea0', chartreuse: '7fff00', chocolate: 'd2691e',
    coral: 'ff7f50', cornflowerblue: '6495ed', cornsilk: 'fff8dc', crimson: 'dc143c',
    cyan: '00ffff', darkblue: '00008b', darkcyan: '008b8b', darkgoldenrod: 'b8860b',
    darkgray: 'a9a9a9', darkgreen: '006400', darkgrey: 'a9a9a9', darkkhaki: 'bdb76b',
    darkmagenta: '8b008b', darkolivegreen: '556b2f', darkorange: 'ff8c00',
    darkorchid: '9932cc', darkred: '8b0000', darksalmon: 'e9967a', darkseagreen: '8fbc8f',
    darkslateblue: '483d8b', darkslategray: '2f4f4f', darkslategrey: '2f4f4f',
    darkturquoise: '00ced1', darkviolet: '9400d3', deeppink: 'ff1493',
    deepskyblue: '00bfff', dimgray: '696969', dimgrey: '696969', dodgerblue: '1e90ff',
    firebrick: 'b22222', floralwhite: 'fffaf0', forestgreen: '228b22', fuchsia: 'ff00ff',
    gainsboro: 'dcdcdc', ghostwhite: 'f8f8ff', gold: 'ffd700', goldenrod: 'daa520',
    gray: '808080', green: '008000', greenyellow: 'adff2f', grey: '808080',
    honeydew: 'f0fff0', hotpink: 'ff69b4', indianred: 'cd5c5c', indigo: '4b0082',
    ivory: 'fffff0', khaki: 'f0e68c', lavender: 'e6e6fa', lavenderblush: 'fff0f5',
    lawngreen: '7cfc00', lemonchiffon: 'fffacd', lightblue: 'add8e6', lightcoral: 'f08080',
    lightcyan: 'e0ffff', lightgoldenrodyellow: 'fafad2', lightgray: 'd3d3d3',
    lightgreen: '90ee90', lightgrey: 'd3d3d3', lightpink: 'ffb6c1', lightsalmon: 'ffa07a',
    lightseagreen: '20b2aa', lightskyblue: '87cefa', lightslategray: '778899',
    lightslategrey: '778899', lightsteelblue: 'b0c4de', lightyellow: 'ffffe0',
    lime: '00ff00', limegreen: '32cd32', linen: 'faf0e6', magenta: 'ff00ff',
    maroon: '800000', mediumaquamarine: '66cdaa', mediumblue: '0000cd',
    mediumorchid: 'ba55d3', mediumpurple: '9370db', mediumseagreen: '3cb371',
    mediumslateblue: '7b68ee', mediumspringgreen: '00fa9a', mediumturquoise: '48d1cc',
    mediumvioletred: 'c71585', midnightblue: '191970', mintcream: 'f5fffa',
    mistyrose: 'ffe4e1', moccasin: 'ffe4b5', navajowhite: 'ffdead', navy: '000080',
    oldlace: 'fdf5e6', olive: '808000', olivedrab: '6b8e23', orange: 'ffa500',
    orangered: 'ff4500', orchid: 'da70d6', palegoldenrod: 'eee8aa', palegreen: '98fb98',
    paleturquoise: 'afeeee', palevioletred: 'db7093', papayawhip: 'ffefd5',
    peachpuff: 'ffdab9', peru: 'cd853f', pink: 'ffc0cb', plum: 'dda0dd',
    powderblue: 'b0e0e6', purple: '800080', rebeccapurple: '663399', red: 'ff0000',
    rosybrown: 'bc8f8f', royalblue: '4169e1', saddlebrown: '8b4513', salmon: 'fa8072',
    sandybrown: 'f4a460', seagreen: '2e8b57', seashell: 'fff5ee', sienna: 'a0522d',
    silver: 'c0c0c0', skyblue: '87ceeb', slateblue: '6a5acd', slategray: '708090',
    slategrey: '708090', snow: 'fffafa', springgreen: '00ff7f', steelblue: '4682b4',
    tan: 'd2b48c', teal: '008080', thistle: 'd8bfd8', tomato: 'ff6347',
    turquoise: '40e0d0', violet: 'ee82ee', wheat: 'f5deb3', white: 'ffffff',
    whitesmoke: 'f5f5f5', yellow: 'ffff00', yellowgreen: '9acd32'
};

function clamp(v, lo, hi) {
    return Math.min(hi, Math.max(lo, v));
}

function rgbToHsl(r, g, b, a) {
    r /= 255; g /= 255; b /= 255;
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const l = (max + min) / 2;
    let h = 0;
    let s = 0;
    if (max !== min) {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        if (max === r) h = ((g - b) / d + (g < b ? 6 : 0));
        else if (max === g) h = (b - r) / d + 2;
        else h = (r - g) / d + 4;
        h *= 60;
    }
    return { h, s, l, a };
}

function parseHex(hex) {
    if (hex.length === 3 || hex.length === 4) {
        hex = hex.split('').map(function (c) { return c + c; }).join('');
    }
    if (hex.length !== 6 && hex.length !== 8) return null;
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    const a = hex.length === 8 ? parseInt(hex.slice(6, 8), 16) / 255 : 1;
    if ([r, g, b].some(Number.isNaN) || Number.isNaN(a)) return null;
    return rgbToHsl(r, g, b, a);
}

function parseChannel(str, max) {
    str = str.trim();
    if (str.endsWith('%')) {
        const pct = parseFloat(str);
        return Number.isNaN(pct) ? NaN : (pct / 100) * max;
    }
    return parseFloat(str);
}

function parseColor(str) {
    if (typeof str !== 'string') return null;
    str = str.trim().toLowerCase();
    if (!str) return null;

    if (str[0] === '#') return parseHex(str.slice(1));

    if (Object.prototype.hasOwnProperty.call(NAMED_COLORS, str)) {
        return parseHex(NAMED_COLORS[str]);
    }

    let m = str.match(/^rgba?\(\s*([^,\s]+)\s*,\s*([^,\s]+)\s*,\s*([^,\s]+)\s*(?:,\s*([^)\s]+)\s*)?\)$/);
    if (m) {
        const r = parseChannel(m[1], 255);
        const g = parseChannel(m[2], 255);
        const b = parseChannel(m[3], 255);
        const a = m[4] === undefined ? 1 : parseChannel(m[4], 1);
        if ([r, g, b, a].some(Number.isNaN)) return null;
        return rgbToHsl(clamp(r, 0, 255), clamp(g, 0, 255), clamp(b, 0, 255), clamp(a, 0, 1));
    }

    m = str.match(/^hsla?\(\s*([^,\s]+?)(?:deg)?\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([^)\s]+)\s*)?\)$/);
    if (m) {
        const h = parseFloat(m[1]);
        const s = parseFloat(m[2]) / 100;
        const l = parseFloat(m[3]) / 100;
        const a = m[4] === undefined ? 1 : parseChannel(m[4], 1);
        if ([h, s, l, a].some(Number.isNaN)) return null;
        return { h: ((h % 360) + 360) % 360, s: clamp(s, 0, 1), l: clamp(l, 0, 1), a: clamp(a, 0, 1) };
    }

    return null;
}

function formatColor(c) {
    const h = Math.round(c.h * 10) / 10;
    const s = Math.round(c.s * 1000) / 10;
    const l = Math.round(c.l * 1000) / 10;
    const a = Math.round(c.a * 1000) / 1000;
    return 'hsla(' + h + ', ' + s + '%, ' + l + '%, ' + a + ')';
}

function isDarkColor(c) {
    return c.l < 0.5;
}

// Hex form for legacy HTML color attributes (bgcolor, font color, body
// text/link), which ignore functional notations like hsla()
function formatHexColor(c) {
    const hueToRgb = (p, q, t) => {
        if (t < 0) t += 1;
        if (t > 1) t -= 1;
        if (t < 1 / 6) return p + (q - p) * 6 * t;
        if (t < 1 / 2) return q;
        if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
        return p;
    };
    let r;
    let g;
    let b;
    if (c.s === 0) {
        r = g = b = c.l;
    } else {
        const q = c.l < 0.5 ? c.l * (1 + c.s) : c.l + c.s - c.l * c.s;
        const p = 2 * c.l - q;
        const h = c.h / 360;
        r = hueToRgb(p, q, h + 1 / 3);
        g = hueToRgb(p, q, h);
        b = hueToRgb(p, q, h - 1 / 3);
    }
    const toHex = (v) => Math.round(clamp(v, 0, 1) * 255).toString(16).padStart(2, '0');
    return '#' + toHex(r) + toHex(g) + toHex(b);
}

// Background: light surfaces fold into a dark band (lightness order inverted,
// so lighter inputs stay the "brighter" layer relative to each other in the
// dark theme), dark surfaces pass through, the 0.35-0.5 band eases between.
// Text: dark ink lifts into a light band, light ink passes through.
function remapColor(c, role) {
    let l = c.l;
    if (role === 'background') {
        if (l >= 0.5) {
            l = Math.max(0.06, 0.98 - l);
        } else if (l > 0.35) {
            const t = (l - 0.35) / 0.15;
            l = l * (1 - t) + Math.max(0.06, 0.98 - l) * t;
        }
    } else { // text
        if (l < 0.5) {
            l = Math.max(0.75, 1 - l * 0.35);
        } else if (l < 0.75) {
            l = 0.75;
        }
    }
    return { h: c.h, s: Math.min(c.s, 0.85), l: clamp(l, 0, 1), a: c.a };
}

const EmailRemap = { parseColor, formatColor, formatHexColor, remapColor, isDarkColor };

if (typeof module !== 'undefined' && module.exports) module.exports = EmailRemap;
if (typeof window !== 'undefined') window.EmailRemap = EmailRemap;

})();
