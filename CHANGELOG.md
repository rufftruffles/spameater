# Changelog

## 4.0.0 — 2026-08-22

### Email viewer
- HTML mail is color-remapped to the dark interface per color (hue preserved, luminance inverted for light designs) instead of being overridden with forced styles. Mail that is already dark renders as sent.
- Fixed: email `<style>` blocks were stripped during sanitization, so styled mail lost its layout entirely (`WHOLE_DOCUMENT` sanitize).
- Fixed: `<body>` attributes (background colors) were dropped from the rendered frame.
- Remote images are blocked by default and replaced with placeholders; a per-email button loads them. CSS background images from remote hosts are stripped the same way.
- Reverted the v3 rendering workarounds (hidden `hr`, removed table borders, scanline overlay).
- Email modal is fullscreen on phones; wide fixed-width mail scrolls horizontally inside the frame.

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
