# SpamEater v4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship SpamEater v4: correct dark rendering of HTML email, Terminal Ledger visual refresh, dependency/security foundation fixes, and the copy/dice/TTL quick wins.

**Architecture:** Frontend stays vanilla JS with no build step; a new standalone color-remap module (pure functions, dual browser/Node loading) powers the email viewer; the API and Haraka plugin gain an additive `expires_at` field; Docker entrypoint moves secrets to the data volume. Tests use `node:test` only.

**Tech Stack:** Node 22, Express, Haraka, SQLite, vanilla JS frontend, node:test, playwright MCP for E2E/screenshots.

**Spec:** `docs/superpowers/specs/2026-08-22-spameater-v4-design.md`

## Global Constraints

- Branch: all work on `v4`. Commit after every task. NO Claude signature lines in commit messages (repo hook rejects them).
- No new runtime dependencies. Tests: `node:test` only. No bundler, no framework.
- Design tokens (exact values, from spec §2): bg `#0a0c09`; surfaces `#0e120c` / `#0c0f0b`; hairlines `#1c241a` / `#2a331f`; text `#eef4ea` / `#d8e2d4` / `#7d8a76`; faint `#4d5947`; accent `#a3e635`.
- Fonts: JetBrains Mono + Space Grotesk, self-hosted woff2 in `frontend/fonts/`. No requests to google fonts or cdnjs anywhere in the shipped app.
- Iframe invariant: `sandbox="allow-same-origin"`, never add `allow-scripts`.
- All user-facing prose (UI strings, README) is written per the repo skill `ai-writing-tells.skill` (extracted at `/tmp/claude-1000/-home-agnostic-Claude-spameater/34cf1bc1-42e8-42bb-b092-41a5ee5d495b/scratchpad/skills-ext/ai-writing-tells/` — read `references/rewriting.md` before writing copy): plain statements, no rule-of-three, no negative parallelism, minimal em dashes/bold, no significance-announcing closers.
- Production paths default to `/opt/spameater` but must respect a `SPAMEATER_HOME` env override (introduced Task 2) so tests and screenshots can run unprivileged.

---

### Task 1: Dependency manifest and lockfile

**Files:**
- Create: `package.json`, `.npmrc` (save-exact)
- Modify: `.gitignore` (remove blanket `*.json`)
- Modify: `.github/workflows/docker-publish.yml` (add ci/audit/test gates)

**Interfaces:**
- Produces: `npm test` runs `node --test test/`; all later tasks rely on it.

- [ ] **Step 1: Fix .gitignore.** Delete the `*.json` line; add targeted replacements so runtime data stays ignored: `data/`, `*.db`, `logs/`. Verify with `git check-ignore -v package.json` → no match.
- [ ] **Step 2: Create package.json** (versions = current latest at implementation time; pin exact):

```json
{
  "name": "spameater",
  "version": "4.0.0",
  "private": true,
  "description": "Privacy-focused disposable email service with automatic 24-hour deletion.",
  "license": "MIT",
  "engines": { "node": ">=22" },
  "scripts": {
    "start": "node api-server.js",
    "test": "node --test test/"
  },
  "dependencies": {
    "express": "<pin>",
    "helmet": "<pin>",
    "express-rate-limit": "<pin>",
    "sqlite3": "<pin>",
    "isomorphic-dompurify": "<pin>"
  }
}
```

Resolve each `<pin>` with `npm view <pkg> version` and write the exact number. Add `.npmrc` containing `save-exact=true`.
- [ ] **Step 3:** `npm install` → lockfile appears; `npm ls --depth=0` clean; commit `package.json`, `package-lock.json`, `.npmrc`, `.gitignore`.
- [ ] **Step 4: CI gates.** In `docker-publish.yml`, before the build job steps, insert: setup-node 22, `npm ci`, `npm audit --audit-level=high`, `npm test`. Commit.

### Task 2: Path override + delete-token hardening + first tests

**Files:**
- Create: `lib/delete-token.js`, `test/delete-token.test.js`
- Modify: `api-server.js` (use lib; `SPAMEATER_HOME`), `haraka/plugins/save_email.js` (`SPAMEATER_HOME`)

**Interfaces:**
- Produces: `lib/delete-token.js` exporting `generateDeleteToken(secret, prefix, emailId, windowOffset=0)` → hex string, and `verifyDeleteToken(secret, prefix, emailId, token)` → boolean (accepts current + previous 5-min window; constant-time; length-guarded).

- [ ] **Step 1:** Add near the top of `api-server.js` and `save_email.js`: `const SPAMEATER_HOME = process.env.SPAMEATER_HOME || '/opt/spameater';` and replace every hardcoded `/opt/spameater` string with it (api-server.js:19-21; save_email.js:11-12,392).
- [ ] **Step 2: Write failing tests** in `test/delete-token.test.js` using `node:test` + `assert`:

```js
const { test } = require('node:test');
const assert = require('node:assert');
const { generateDeleteToken, verifyDeleteToken } = require('../lib/delete-token.js');
const S = 'x'.repeat(32);

test('current window verifies', () => {
  const t = generateDeleteToken(S, 'foo', 'id1');
  assert.equal(verifyDeleteToken(S, 'foo', 'id1', t), true);
});
test('previous window verifies', () => {
  const t = generateDeleteToken(S, 'foo', 'id1', -1);
  assert.equal(verifyDeleteToken(S, 'foo', 'id1', t), true);
});
test('two windows back fails', () => {
  const t = generateDeleteToken(S, 'foo', 'id1', -2);
  assert.equal(verifyDeleteToken(S, 'foo', 'id1', t), false);
});
test('wrong-length token returns false, never throws', () => {
  assert.equal(verifyDeleteToken(S, 'foo', 'id1', 'ab'), false);
  assert.equal(verifyDeleteToken(S, 'foo', 'id1', ''), false);
  assert.equal(verifyDeleteToken(S, 'foo', 'id1', 'z'.repeat(64)), false);
});
```

- [ ] **Step 3:** Run `npm test` → fails (module missing).
- [ ] **Step 4: Implement `lib/delete-token.js`** by extracting the existing HMAC logic from api-server.js (5-min window math unchanged) and guarding length:

```js
const crypto = require('crypto');
const WINDOW_MS = 5 * 60 * 1000;

function generateDeleteToken(secret, prefix, emailId, windowOffset = 0) {
  const window = Math.floor(Date.now() / WINDOW_MS) + windowOffset;
  return crypto.createHmac('sha256', secret)
    .update(`${prefix}:${emailId}:${window}`).digest('hex');
}

function verifyDeleteToken(secret, prefix, emailId, token) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return false;
  for (const off of [0, -1]) {
    const expected = generateDeleteToken(secret, prefix, emailId, off);
    if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) return true;
  }
  return false;
}
module.exports = { generateDeleteToken, verifyDeleteToken };
```

- [ ] **Step 5:** Wire api-server.js to the lib (delete its inline duplicates, keep its token cache), run `npm test` → pass, start API once with `SPAMEATER_HOME=$(mktemp -d)` to smoke it, commit.

### Task 3: Color remap engine (pure functions)

**Files:**
- Create: `frontend/email-remap.js`, `test/email-remap.test.js`

**Interfaces:**
- Produces (attached to `window.EmailRemap` in browsers, `module.exports` in Node):
  - `parseColor(str)` → `{h,s,l,a}` or `null` (hex 3/6/8, rgb/rgba, hsl/hsla, CSS named colors)
  - `formatColor({h,s,l,a})` → `"hsla(h, s%, l%, a)"`
  - `remapColor(color, role)` → color; `role` is `'background'` or `'text'`
  - `isDarkColor(color)` → boolean (l < 0.5)
  - Task 4 consumes all of these.

- [ ] **Step 1: Failing tests** in `test/email-remap.test.js` (representative set; add cases as needed):

```js
const { test } = require('node:test');
const assert = require('node:assert');
const R = require('../frontend/email-remap.js');

test('parses hex, rgb, named', () => {
  assert.deepEqual(R.parseColor('#fff').l, 1);
  assert.equal(R.parseColor('rgb(255, 0, 0)').h, 0);
  assert.equal(R.parseColor('white').l, 1);
  assert.equal(R.parseColor('bogus(1)'), null);
});
test('light background goes dark, hue preserved', () => {
  const out = R.remapColor(R.parseColor('#e8f0fe'), 'background');
  assert.ok(out.l < 0.2);
  assert.ok(Math.abs(out.h - R.parseColor('#e8f0fe').h) < 1);
});
test('dark text goes light', () => {
  const out = R.remapColor(R.parseColor('#222222'), 'text');
  assert.ok(out.l > 0.75);
});
test('already-dark background barely moves', () => {
  const inC = R.parseColor('#101418');
  const out = R.remapColor(inC, 'background');
  assert.ok(Math.abs(out.l - inC.l) < 0.08);
});
test('alpha preserved', () => {
  assert.equal(R.remapColor(R.parseColor('rgba(255,255,255,0.5)'), 'background').a, 0.5);
});
```

- [ ] **Step 2:** `npm test` → fails.
- [ ] **Step 3: Implement.** Mapping rule (backgrounds): `l' = clamp(0.04, 0.96 - l * 0.82, 0.96)` folded through role — i.e. background lightness inverts around the midpoint into a dark band (`l>0.5 → l' = 0.98 - l`, floor 0.06), dark backgrounds stay (`l<=0.35` unchanged), the 0.35–0.5 band eases linearly between behaviors. Text: mirror image (dark text `l<0.5 → l' = 1 - l*0.35` capped ≥0.75; light text unchanged). Saturation capped at 0.85 after remap; hue and alpha never change. File ends with the dual-export footer:

```js
const EmailRemap = { parseColor, formatColor, remapColor, isDarkColor };
if (typeof module !== 'undefined' && module.exports) module.exports = EmailRemap;
if (typeof window !== 'undefined') window.EmailRemap = EmailRemap;
```

Named-color table: embed the standard 148 CSS names (generate once with a scratch script from a known list; commit the literal table).
- [ ] **Step 4:** `npm test` → pass. Commit.

### Task 4: Viewer transform — DOM walk, image blocking, new srcdoc

**Files:**
- Modify: `frontend/app.js` (replace `displayEmailContent` iframe branch at ~`:715-794`), `frontend/index.html` (load `email-remap.js` before `app.js`; add "Load images" button to modal header)

**Interfaces:**
- Consumes: `window.EmailRemap` from Task 3.
- Produces: `transformEmailDocument(html, { allowRemoteImages })` → `{ html, blockedImages }` defined in app.js; modal state `this.currentEmailAllowsImages`.

- [ ] **Step 1: Implement `transformEmailDocument`.** Pipeline: `DOMPurify.sanitize` (existing config) → `document.implementation.createHTMLDocument('email')`, `doc.documentElement.innerHTML = clean` → walk:
  - every element's inline `style`: for each of `color`, `background-color`, `border(-top/right/bottom/left)?-color`: parse, `remapColor` with role text/background/text; `background` shorthand: regex out color tokens and remap them, leave url() parts;
  - attributes `bgcolor`/`text`/`link`/`alink`/`vlink`: remap and rewrite;
  - every `<style>` element: iterate `doc.styleSheets[i].cssRules`, rewrite the same properties on each style rule, serialize back via `rule.cssText` join;
  - **dark-mail detection first**: resolve effective background of `body` (body inline/bgcolor, else first full-bleed wrapper, else white); if `isDarkColor` → skip all color rewriting;
  - image blocking when `!allowRemoteImages`: `<img>` with `src` matching `/^https?:/i` → set `src` to `PLACEHOLDER_SVG` (inline data-URI: 1px-border box, image glyph, alt text kept), keep original in nothing (re-render reruns pipeline), increment count; strip `url(http...)` from any inline/sheet `background`/`background-image`.
  - Return serialized `doc.documentElement.outerHTML` + count.
- [ ] **Step 2: New srcdoc wrapper.** Base stylesheet without `!important` and without forcing colors: font stack, `line-height 1.6`, `img{max-width:100%;height:auto}`, `body{margin:0;padding:16px;background:#0c0f0b;color:#d8e2d4;word-wrap:break-word}` — body colors act as defaults only (mail with own colors was remapped, unstyled mail inherits these). Keep `<meta name="viewport">`. Delete the v3 band-aid rules (forced `td,th` border:none, hidden `hr` — reverts commits `c4f1c65`, `b6a39bd` behavior).
- [ ] **Step 3: Load-images control.** Modal header button, hidden when count 0, label `Load images (N)`; click → re-render current email with `allowRemoteImages: true`, hide button. Plain-text path unchanged apart from token colors.
- [ ] **Step 4: Manual check with fixtures.** Create `test/fixtures/` with 3 sample emails (light marketing table mail, dark-designed mail, unstyled text/html) as .html files; open the app locally (Task 8 dev server) and eyeball all three render correctly; wide mail scrolls horizontally inside iframe.
- [ ] **Step 5:** `npm test` still green. Commit.

### Task 5: Terminal Ledger visual system

**Files:**
- Modify: `frontend/style.css` (rewrite), `frontend/index.html` (structure, SVG icons, confirm dialog markup, copy/dice/TTL controls), `frontend/404.html`, `frontend/50x.html`
- Create: `frontend/fonts/` (JetBrains Mono 400/700, Space Grotesk 400/600 woff2 + `@font-face` block), `frontend/vendor/dompurify.min.js`
- Modify: CSP in `frontend/index.html:13`, `deploy/nginx.conf:21`, `docker/nginx-docker.conf:20`

**Interfaces:**
- Produces: CSS custom properties `--bg --surface --surface-2 --line --line-strong --text --text-body --text-dim --text-faint --accent` with the Global Constraints values; class names consumed by Task 6: `.copy-btn`, `.dice-btn`, `.ttl-chip`, `.confirm-overlay`, `.load-images-btn`.

- [ ] **Step 1: Vendor assets.** Download DOMPurify at the version pinned in package.json (`isomorphic-dompurify`'s bundled dompurify version; use its `node_modules/dompurify/dist/purify.min.js` copy — no network trust needed) into `frontend/vendor/`. Download woff2s for the two families (google fonts css2 API with a woff2 UA, or gfonts mirror), place in `frontend/fonts/`, write `@font-face` rules at the top of style.css with `font-display: swap` and system fallback stacks (`ui-monospace, monospace` / `system-ui, sans-serif`).
- [ ] **Step 2: Rewrite style.css** from the Direction A mockup (`scratchpad/v4/Main.dc.html` + `TerminalInbox.dc.html` are the reference): tokens as CSS custom properties, faint 64px background grid via two linear-gradients at 0.5 opacity, square corners everywhere, hairline borders, uppercase mono micro-labels with 0.1em tracking, accent-on-dark buttons (`background: var(--accent); color: var(--bg)`), scanline overlay and glow effects deleted. Responsive: single column under 640px, modal fullscreen under 640px, inputs stack.
- [ ] **Step 3: Restructure index.html.** Keep all existing element ids (app.js depends on them). Replace every emoji icon with inline stroke SVG (16/20px, `stroke-width 2`, copy the exact paths from the mockup files). Add: copy button + dice button beside both address inputs; TTL chip in inbox top bar (`<span class="ttl-chip" id="ttlChip" hidden></span>`); confirm dialog markup before `</body>`:

```html
<div class="confirm-overlay" id="confirmOverlay" hidden role="alertdialog" aria-modal="true" aria-labelledby="confirmText">
  <div class="confirm-box">
    <p id="confirmText"></p>
    <div class="confirm-actions">
      <button id="confirmCancel" class="btn-ghost">Keep it</button>
      <button id="confirmOk" class="btn-danger">Delete</button>
    </div>
  </div>
</div>
```

Fix the fullscreen toggle icon ternary (app.js:840-853 both branches `'⛶'`) → two distinct SVGs (expand/compress). UI copy per ai-writing-tells (read `references/rewriting.md` first; e.g. empty state stays in brand voice: "Ready to eat spam." + one plain sentence).
- [ ] **Step 4: CSP ×3.** Remove `https://cdnjs.cloudflare.com` and `https://fonts.googleapis.com`/`gstatic` from all three CSP definitions; script/style/font sources become `'self'` (+ existing inline allowances). Point `index.html` scripts at `vendor/dompurify.min.js`, `email-remap.js`, `app.js`. Also restyle `404.html`/`50x.html` with the token palette.
- [ ] **Step 5:** `npm test` green (no JS logic touched), visual check via dev server, commit.

### Task 6: Quick wins in app.js

**Files:**
- Modify: `frontend/app.js`
- Create: `test/prefix-validation.test.js`

**Interfaces:**
- Consumes: Task 5 classes/ids; `expires_at` field from Task 7 (feature-detect: chip hidden when absent).
- Produces: `randomPrefix()` → string matching `^[a-z]+-[a-z]+[0-9]{2}$`. The canonical prefix regex stays where it is today (app.js); the test in step 5 locks its behavior by copying it verbatim.

- [ ] **Step 1: Copy buttons.** `navigator.clipboard.writeText(fullAddress)` with fallback `document.execCommand('copy')` on a temp input; success toast "Address copied."; wire both landing and inbox instances.
- [ ] **Step 2: Dice.** Embed two ~48-word lists (short, lowercase, no profanity-adjacent words), pick with `crypto.getRandomValues`: `adjective-noun` + 2 digits, e.g. `midnight-fox42`. Landing dice fills the input; inbox dice fills switcher; both leave submission to the user.
- [ ] **Step 3: TTL countdown.** On inbox load/poll, read `expires_at` from inbox JSON when present; chip shows `Self-destructs in HH:MM:SS`, ticks via 1s interval only while tab visible, turns `--accent`→warning tone under 1h (add `--warn: #e6c229` token in Task 5 if not present — add it there now). Hidden when field absent.
- [ ] **Step 4: Styled confirm.** Replace `confirm()` (app.js:1048) with a promise-based `confirmDialog(text)` using Task 5 markup; Escape/backdrop = cancel; focus moves to Cancel on open and back on close.
- [ ] **Step 5: Test** `test/prefix-validation.test.js`: copy the exact regex from app.js into the test (locking it) and assert accepts `a`, `my-email`, `a1.b2`, rejects `''`, `.a`, `a.`, `a..b`, 51 chars. Run, pass, commit.

### Task 7: expires_at in inbox JSON + create response

**Files:**
- Modify: `haraka/plugins/save_email.js` (JSON writer ~`:244-314`), `api-server.js` (`/api/inbox/create` handler ~`:424`, its JSON writer)

**Interfaces:**
- Produces: inbox JSON gains top-level `"expires_at": "<ISO8601>"` (the inbox row's `expires_at`); `POST /api/inbox/create` response body gains the same field. Additive only; Task 6 consumes.

- [ ] **Step 1:** In both JSON writers, include `expires_at` read from the `inboxes` row (both code paths already query or insert the row; select `expires_at` alongside). ISO string via `new Date(row.expires_at).toISOString()` if stored as SQLite datetime text, else pass through.
- [ ] **Step 2:** Add to create-endpoint response JSON.
- [ ] **Step 3:** Smoke: run API with temp `SPAMEATER_HOME`, POST create, assert field present (curl). `npm test` green. Commit.

### Task 8: Dev server + E2E fixtures

**Files:**
- Create: `scripts/dev.js` (static frontend + /api proxy to 3001, port 8080, dev only), `test/fixtures/seed-inbox.js` (writes a sample inbox JSON with 4 emails incl. one light-HTML mail, one dark, one plain-text, `expires_at` ~22h out)

**Interfaces:**
- Produces: `node scripts/dev.js` serves the app at `http://localhost:8080` against `SPAMEATER_HOME=$PWD/.devhome`; used by Task 4 step 4, Task 9, Task 10.

- [ ] **Step 1:** `scripts/dev.js`: plain `node:http`, serve `frontend/` files (correct MIME for html/css/js/woff2/svg), substitute `EMAIL_DOMAIN_PLACEHOLDER`→`spameater.io` when serving index.html, proxy `/api/*` to `127.0.0.1:3001`, serve `/api/inbox/*.json` straight from `$SPAMEATER_HOME/data/inboxes/`.
- [ ] **Step 2:** `seed-inbox.js` writes `.devhome/data/inboxes/midnight-fox42.json` in the exact shape `save_email.js` produces (copy field names from its writer) + `expires_at`.
- [ ] **Step 3:** Boot API (`SPAMEATER_HOME=$PWD/.devhome node api-server.js`) + dev server, seed, playwright: create flow works, inbox lists 4 emails, modal renders each fixture correctly, images-blocked button appears on the light mail. Add `.devhome/` to `.gitignore`. Commit.

### Task 9: Docker + deploy fixes

**Files:**
- Modify: `docker/entrypoint.sh`, `docker-compose.yml`, `docker/docker-compose.yml`, `setup.sh`, `docker/docker-setup.sh`, `docker/Dockerfile`

**Interfaces:** none downstream.

- [ ] **Step 1: Secret persistence** in `entrypoint.sh` (replacing lines ~22-45):

```bash
ENV_FILE=/opt/spameater/data/.env
LEGACY_ENV=/opt/spameater/.env
if [ -z "$ENCRYPTION_KEY" ] && [ ! -f "$ENV_FILE" ] && [ -f "$LEGACY_ENV" ]; then
    cp "$LEGACY_ENV" "$ENV_FILE"   # restart-in-place migration
fi
if [ -z "$ENCRYPTION_KEY" ] && [ -f "$ENV_FILE" ]; then
    . "$ENV_FILE"
fi
gen_secret() { openssl rand -hex 16; }   # exactly 32 chars, full entropy
[ -n "$DELETE_TOKEN_SECRET" ] || DELETE_TOKEN_SECRET=$(gen_secret)
[ -n "$CSRF_SECRET" ] || CSRF_SECRET=$(gen_secret)
[ -n "$ENCRYPTION_KEY" ] || ENCRYPTION_KEY=$(gen_secret)
printf 'DELETE_TOKEN_SECRET=%s\nCSRF_SECRET=%s\nENCRYPTION_KEY=%s\n' \
  "$DELETE_TOKEN_SECRET" "$CSRF_SECRET" "$ENCRYPTION_KEY" > "$ENV_FILE"
chmod 600 "$ENV_FILE"
```

Keep writing the app-visible `/opt/spameater/.env` as before but `chmod 600`; **delete the `chmod 644` line (~:255)**. Note: `openssl rand -hex 16` fixes the truncated-entropy bug (`tr -d` before `cut`) at the same time.
- [ ] **Step 2:** Both compose files: drop `version:` key from root file, delete the explicit empty-string secret env entries (comment shows how to set them explicitly), align root file to `${EMAIL_DOMAIN}` style like `docker/docker-compose.yml`.
- [ ] **Step 3: Haraka pin.** `npm install -g Haraka@<current version>` (resolve with `npm view Haraka version`) in `setup.sh:147` and `docker/docker-setup.sh:24`; app deps installed with `npm ci` from the committed lockfile instead of bare `npm install` (`setup.sh:161-166`, `docker-setup.sh:43-47`, Dockerfile).
- [ ] **Step 4:** `docker compose config` parses both files; `bash -n` every touched script; commit.

### Task 10: Screenshots + README + release notes

**Files:**
- Modify: `README.md`, `screenshots/1.png` `2.png` `3.png`
- Create: `CHANGELOG.md` (v4 section)

**Interfaces:** none.

- [ ] **Step 1:** Bring up dev server + seeded inbox (Task 8). Playwright at 1440×900: capture landing → `screenshots/1.png`, populated inbox → `2.png`, open email modal (light-HTML fixture, images-blocked banner visible) → `3.png`.
- [ ] **Step 2: README rewrite.** Read ai-writing-tells `references/rewriting.md` first. Update: "What's New in v4" (viewer remap, Terminal Ledger, image blocking, self-hosted assets, secrets fix, manifest+tests, quick wins), feature list, screenshots captions, corrected claims (drop "TLS 1.2+ only" implication for SMTP; external-dependency claim now true), fix the dead `QUICKSTART.md` link, keep install instructions intact. Clean-mode self-review pass before committing.
- [ ] **Step 3:** `CHANGELOG.md` with a factual v4.0.0 list. Commit.

### Task 11: Full verification + wrap-up

- [ ] **Step 1:** `npm test` all green; `npm audit --audit-level=high` clean; `bash -n` on all shell scripts; `git grep -nE 'cdnjs|fonts.googleapis'` returns only docs/spec references (none in `frontend/`, `deploy/`, `docker/`).
- [ ] **Step 2:** Playwright pass at 390×844: landing usable, inbox readable, modal fullscreen, fixtures render, horizontal scroll on wide mail.
- [ ] **Step 3:** Update memory `v4-scope.md` status; final commit. Tag/merge/release only on owner's word.
