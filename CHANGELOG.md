# Changelog

## 4.0.1 — 2026-08-22

- ModSecurity works on Enterprise Linux 10: when EPEL has no nginx connector, the installer falls back to binary RPMs from the `mikelo2/modsecurity-el10` COPR (built on Fedora infrastructure against the distro nginx).
- Fixed the WAF enable gates: dynamic modules never appear in `nginx -V` (the check now looks for the module file), and a malformed bracket skipped the post-SSL include step.
- The ModSecurity audit log is created at install owned by the nginx worker; it was previously never written.
- EPEL is installed in the dnf path (certbot and fail2ban need it on a minimal system); EL10 added to supported systems.
- Install scripts restyled to the Terminal Ledger theme; the setup summary no longer prints secrets.
- The Haraka-directory npm install carries the same dependency overrides as the repo manifest, clearing its audit warnings.
- Delivery works on Haraka 3.3 (address API change; fresh installs pin 3.3.3).

## 4.0.0 — 2026-08-22

### Email ingestion
- Forwarded and attachment-bearing mail extracts correctly: the full MIME tree is walked instead of one level of children (was "No content available" for every forward).
- Inline images referenced by `Content-ID` are embedded into the stored HTML as data URIs (raster formats only, 200KB per image, 400KB per message), so signature logos render.
- Subjects and From headers are trimmed of trailing newlines.
- Compatible with both the Haraka 3.1 method API and the 3.3 property API for addresses (fresh installs pin Haraka 3.3.3 and failed delivery without this).

### Email viewer
- HTML mail is color-remapped to the dark interface per color (hue preserved, luminance inverted for light designs) instead of being overridden with forced styles. Mail that is already dark renders as sent.
- Fixed: email `<style>` blocks were stripped during sanitization, so styled mail lost its layout entirely (`WHOLE_DOCUMENT` sanitize).
- Fixed: `<body>` attributes (background colors) were dropped from the rendered frame.
- Remote images are blocked by default and replaced with placeholders; a per-email button loads them. CSS background images from remote hosts are stripped the same way.
- Reverted the v3 rendering workarounds (hidden `hr`, removed table borders, scanline overlay).
- Email modal is fullscreen on phones; wide fixed-width mail scrolls horizontally inside the frame.
- A post-render contrast guard verifies every text's computed color against its effective background and lifts unreadable text (catches legacy `font[color]` attributes, system color keywords, and inheritance the source transform cannot see). Legacy color attributes are remapped as hex, which is the only notation they accept.
- Links open in a new tab with `noopener noreferrer`; the sandbox allows popups only, scripts remain forbidden.
- The frame declares `color-scheme: dark` (dark scrollbars) and gives unstyled `hr` dividers a subtle line.
- Blocking also covers protocol-relative URLs, `srcset` candidates, and CSS background images; `cid:` references without a stored image show a placeholder.

### Interface
- New Terminal Ledger design: dark palette with a single lime accent, JetBrains Mono + Space Grotesk (self-hosted), SVG icons throughout, restyled error pages.
- No third-party CDN requests: DOMPurify is vendored, fonts are served locally, all three CSP copies tightened to `'self'`.
- Copy-address button, crypto-random address generator, live self-destruct countdown, and a styled delete confirmation replacing `window.confirm()`.
- Fixed the fullscreen toggle showing the same icon in both states.

### Server and data
- Inbox JSON and the create response now include `expires_at`.
- Delete-token verification no longer throws on wrong-length tokens (was a process crash under Express 4 semantics); token logic extracted to `lib/delete-token.js` with tests.
- `SPAMEATER_HOME` environment variable overrides the `/opt/spameater` install prefix for development and testing.

### Docker and deployment
- Secrets persist on the data volume: container recreation and image upgrades reuse the existing `ENCRYPTION_KEY` instead of silently regenerating it and orphaning all stored mail. Explicitly-set environment variables still win.
- `.env` is mode 600 (was world-readable 644 inside the container).
- Secret generation uses `openssl rand -hex 16` (the old pipeline could produce short values).
- Haraka and all npm dependencies pinned; native installer installs the same versions.
- CI runs `npm ci`, `npm audit`, and the test suite before building and publishing images.

### Project
- `package.json` with exact-pinned dependencies and a committed lockfile (`.gitignore` no longer excludes all JSON files).
- First test suite (`node:test`): color remap engine, delete tokens, prefix validation.
- Local dev server (`scripts/dev.js`) and inbox seeder (`scripts/seed-inbox.js`) that run without root.
- Install and uninstall scripts restyled to the Terminal Ledger theme (ANSI colors on a TTY, plain text otherwise); the setup summary no longer prints secrets to the terminal, and the unused database password is gone.
