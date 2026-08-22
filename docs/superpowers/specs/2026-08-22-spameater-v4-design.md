# SpamEater v4 — Design Spec

Date: 2026-08-22
Status: approved direction, pending final review
Mockups: Terminal Ledger direction (Direction A), picked from three-direction canvas.

## Overview

v4 is a front-to-back refresh of SpamEater's user-facing layer plus a small set of
foundation fixes that current operation depends on. The four tracks:

1. Email viewer overhaul — correct rendering of HTML mail in a dark UI, with remote
   images blocked by default. Fixes the defect that motivated the release.
2. Visual refresh — new "Terminal Ledger" design system across all screens.
3. Foundation — dependency manifest, Docker secret persistence, two security fixes.
4. Quick wins — copy button, random address generator, TTL countdown, README and
   screenshot refresh.

## Goals

- HTML emails render the way their senders intended, adapted to a dark surface
  without breaking layout or color relationships.
- Mobile email reading works at 390 px widths.
- Tracking pixels in email bodies never fire without an explicit user action.
- The web app loads nothing from third-party CDNs.
- The repo has a dependency manifest, a lockfile, and its first tests.
- `docker compose pull && up -d` no longer destroys stored email.

## Non-goals (deferred, recorded for later releases)

- Delete-token authorization model (tokens are currently mintable by anyone for any
  inbox; unchanged in v4).
- Plaintext inbox JSON being world-readable by prefix (inherent to current design).
- SMTP STARTTLS, attachments, search, multiple inboxes, metrics, backup automation.
- Bulk delete (explicitly excluded by owner).

## 1. Email viewer overhaul

### Problem

`frontend/app.js:740-759` injects a stylesheet into the email iframe forcing
`color: #e0e0e0 !important` and a dark background onto every element. HTML mail is
designed against light backgrounds; the override breaks tables, dividers, and
sender color schemes. Commits `0993bec`, `c4f1c65`, `b6a39bd` are band-aids on this
and get reverted by this work.

### Approach: full DOM color remap

After DOMPurify sanitization, the email HTML is parsed into a detached document
(`document.implementation.createHTMLDocument`) and transformed before being
serialized into the iframe `srcdoc`:

- **Color sources walked**: inline `style` attributes; `<style>` sheet rules via
  CSSOM; legacy HTML attributes (`bgcolor`, `text`, `link`, `alink`, `vlink`).
- **Mapping**: each color parsed to HSL (hex, rgb()/rgba(), hsl()/hsla(), named
  colors; unparseable values left untouched). Light backgrounds map into a dark
  band and dark text maps into a light band, in both cases preserving hue and
  scaled saturation, preserving alpha. Mid-range colors move proportionally so
  contrast relationships survive.
- **Dark-mail detection**: effective root/body background luminance is computed
  first; an email that is already dark is left as-is.
- **Unstyled mail**: emails with no color declarations get the app's base dark
  stylesheet — normal specificity, no `!important`.
- The color math lives in a standalone module (pure functions, no DOM) so it is
  unit-testable in Node.

### Iframe model (stated choice)

`sandbox="allow-same-origin"` with no `allow-scripts` is kept — the current safety
model, unchanged. Rationale: the parent needs `contentDocument.scrollHeight` for
auto-height; dropping same-origin would force `allow-scripts` plus a postMessage
measurer inside untrusted content, a worse trade. The invariant "never add
allow-scripts while allow-same-origin is present" is documented in code at the
iframe declaration.

### Remote image blocking

During the remap pass, `<img>` elements with http(s) sources are replaced by an
inline placeholder (data-URI SVG + preserved alt text) and CSS `background-image`
URLs pointing at remote hosts are stripped. The pass counts what it blocked; the
modal shows a "Load images (N)" control that re-renders the same email with the
stripping pass disabled. Per-email, per-view; nothing persisted. `data:` image
sources (already the only non-http form the sanitizer admits) are untouched.

### Mobile

Acceptance criteria of this track, not a separate item:

- Modal is fullscreen below 640 px.
- Iframe fills the viewport width; wide fixed-width mail scrolls horizontally
  inside the iframe rather than breaking the page.
- `<meta name="viewport">` stays in the srcdoc document.
- Verified with playwright at 390×844 and 1280×832.

## 2. Visual system — Terminal Ledger

Tokens (from the picked mockup):

| Token | Value |
|---|---|
| Background | `#0a0c09` |
| Surface / raised surface | `#0e120c` / `#0c0f0b` |
| Hairline / border | `#1c241a` / `#2a331f` |
| Text strong / body / dim | `#eef4ea` / `#d8e2d4` / `#7d8a76` |
| Faint text | `#4d5947` |
| Accent | `#a3e635` |

- Type: JetBrains Mono (UI chrome, labels, addresses) + Space Grotesk (headings,
  body). Both **self-hosted** as woff2 under `frontend/fonts/` — Google Fonts
  links removed.
- DOMPurify vendored at a pinned version under `frontend/vendor/` — cdnjs link
  removed. All three CSP copies (`frontend/index.html`, `deploy/nginx.conf`,
  `docker/nginx-docker.conf`) updated to drop the CDN allowances.
- Square corners, hairline borders, faint 64 px background grid. No scanline
  overlay, no glow effects. Emoji iconography replaced with stroke SVG icons;
  brand voice strings ("Feed the Eater") stay.
- Screens covered: landing, inbox, email modal, 404/50x pages, toasts, and a
  styled confirm dialog replacing `window.confirm()`.
- All user-facing copy written per the repo's `ai-writing-tells` skill (Write
  mode; Clean-mode self-review before delivery).

## 3. Foundation

- **`package.json` + `package-lock.json`, committed.** Pinned: express, helmet,
  express-rate-limit, sqlite3, isomorphic-dompurify; `engines.node >= 22`.
  `.gitignore`'s blanket `*.json` replaced with targeted ignores so manifests can
  live in the repo. Haraka install pinned to a version in `setup.sh` and
  `docker/docker-setup.sh`. CI gains `npm ci`, `npm audit --audit-level=high`,
  and `npm test` before the image build/push.
- **Docker secret persistence.** Secrets move to a volume-backed file
  (`/opt/spameater/data/.env`). Entrypoint order: explicit environment variables
  win; else an existing volume file is loaded; only when neither exists are
  secrets generated and written there, mode 600. The `chmod 644` at
  `docker/entrypoint.sh:255` is removed. Result: container recreation reuses the
  existing `ENCRYPTION_KEY`; stored mail stays decryptable across upgrades.
- **`timingSafeEqual` crash fix** (`api-server.js`): token length/format is
  validated before comparison so a wrong-length `X-Delete-Token` header returns
  403 instead of throwing inside the async handler.

## 4. Quick wins

- **Copy address**: one-click `navigator.clipboard` copy with toast confirmation,
  on both landing (after create) and inbox views.
- **Random address**: dice control generating a crypto-random word-pair prefix
  (e.g. `midnight-fox42`), on landing and inbox.
- **TTL countdown**: chip showing time until inbox expiry. Requires `expires_at`
  in the inbox JSON (written by `save_email.js` and `api-server.js`) and in the
  create response; countdown ticks client-side.

## 5. README + screenshots

- README rewritten for v4 (ai-writing-tells governs prose): what's new, updated
  feature list, corrected claims (external-CDN and TLS statements currently
  overstate; v4 makes the CDN claim true and drops the SMTP TLS implication).
- `screenshots/*.png` replaced with playwright captures of the real v4 UI seeded
  with sample emails: landing, populated inbox, open email modal. Saved to
  `./screenshots/`.

## 6. Testing

`node:test`, zero new runtime dependencies:

- Color remap module: parse/transform round-trips, luminance mapping, dark-mail
  detection thresholds, sample light/dark/mixed fixtures.
- Delete-token HMAC: window rotation, previous-window acceptance, length-mismatch
  rejection (regression test for the crash fix).
- Prefix validation regex against the documented accept/reject cases.

E2E: playwright pass over create → receive (telnet fixture) → read → delete at
desktop and 390 px widths, used for the screenshot capture as well.

## Compatibility notes

- Existing native installs: no schema change; new JSON field `expires_at` is
  additive; old JSON files regenerate on next email or cleanup cycle.
- Existing Docker installs: if the running container still has its generated
  `.env` (restart, not recreate), first start after upgrade copies it into the
  volume file. On a recreate the old key is already gone — same data loss the
  current versions have on every recreate; with the 24-hour TTL the exposure is
  at most one day of mail, and from v4 on the key persists. Documented in README.

## Release

Version v4.0.0, tagged. Image publish flow unchanged apart from the added CI
gates.
