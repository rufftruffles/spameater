// SpamEater Frontend Application - Security Enhanced
// Secure, minimal JavaScript for email management

// Shown in place of a remote image until the reader loads images for the email
const BLOCKED_IMAGE_PLACEHOLDER = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="160" height="90" viewBox="0 0 160 90">' +
    '<rect x="0.5" y="0.5" width="159" height="89" fill="#0e120c" stroke="#2a331f"/>' +
    '<path d="M62 32 h36 v26 h-36 z M62 50 l10-9 8 7 7-6 11 8" fill="none" stroke="#4d5947" stroke-width="2"/>' +
    '<circle cx="72" cy="39" r="2.5" fill="#4d5947"/>' +
    '</svg>'
);

class SpamEater {
    constructor() {
        this.currentEmail = null;
        this.pollInterval = null;
        this.pollRate = 3000; // 3 seconds
        // Get email domain from meta tag or fall back to hostname
        this.domain = this.getEmailDomain();
        this.lastEmailCount = 0;
        this.currentEmailData = null; // Store current email for headers
        this.deleteTokens = new Map(); // Cache delete tokens
        this.csrfToken = null; // Store CSRF token
        this.failedAttempts = 0; // Track failed requests
        this.maxFailedAttempts = 5; // Stop polling after 5 failures
        this.currentRenderData = null; // Email shown in the modal, for re-render
        this.confirmResolver = null; // Pending confirmDialog() promise
        this.confirmReturnFocus = null;
        this.ttlTimer = null; // Countdown interval
        this.inboxExpiresAt = null; // ms epoch of inbox expiry

        this.init();
    }
    
    getEmailDomain() {
        // Check if email domain is specified in meta tag
        const emailDomainMeta = document.querySelector('meta[name="email-domain"]');
        if (emailDomainMeta && emailDomainMeta.content && emailDomainMeta.content !== 'EMAIL_DOMAIN_PLACEHOLDER') {
            return emailDomainMeta.content;
        }
        
        // Try to get from API endpoint as backup
        try {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', '/api/domain', false); // Synchronous for initialization
            xhr.send();
            if (xhr.status === 200) {
                const data = JSON.parse(xhr.responseText);
                if (data.domain && data.domain !== 'EMAIL_DOMAIN_PLACEHOLDER') {
                    return data.domain;
                }
            }
        } catch (e) {
            // Silent fail - fall back to hostname
        }
        
        // Fall back to current hostname without www or subdomain
        let domain = window.location.hostname;
        
        // Remove www if present
        if (domain.startsWith('www.')) {
            domain = domain.substring(4);
        }
        
        // If it's a subdomain (e.g., mail.example.com), try to get the root domain
        const parts = domain.split('.');
        if (parts.length > 2) {
            // Assume the last two parts are the domain (e.g., example.com)
            // This won't work perfectly for domains like .co.uk but handles most cases
            domain = parts.slice(-2).join('.');
        }
        
        return domain;
    }
    
    init() {
        this.bindEvents();
        this.setDomain();
        
        // Get CSRF token first
        this.getCSRFToken().then(() => {
            // Check if we have a stored email session
            const stored = this.getStoredEmail();
            if (stored && this.isValidEmail(stored)) {
                // Normalize stored email to lowercase
                this.showInbox(stored.toLowerCase());
            }
        });
    }
    
    async getCSRFToken() {
        try {
            const response = await fetch('/api/csrf-token');
            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.csrfToken;
                this.failedAttempts = 0; // Reset on success
            } else {
                this.failedAttempts++;
                if (this.failedAttempts >= this.maxFailedAttempts) {
                    this.showToast('Connection issues detected. Please refresh the page.', 'error');
                    this.stopPolling();
                }
            }
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
            this.failedAttempts++;
        }
    }
    
    bindEvents() {
        // Email creation
        const createBtn = document.getElementById('createBtn');
        const emailInput = document.getElementById('emailPrefix');
        
        createBtn?.addEventListener('click', () => this.createEmail());
        emailInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.createEmail();
        });
        emailInput?.addEventListener('input', (e) => this.validateInput(e));
        
        // Home button
        const homeBtn = document.getElementById('homeBtn');
        if (homeBtn) {
            homeBtn.addEventListener('click', this.goHome.bind(this));
        }
        
        // Email switcher
        const switchBtn = document.getElementById('switchBtn');
        const switcherInput = document.getElementById('emailSwitcher');
        
        switchBtn?.addEventListener('click', () => this.switchEmail());
        switcherInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.switchEmail();
        });
        switcherInput?.addEventListener('input', (e) => this.validateInput(e));
        
        // Refresh inbox
        const refreshBtn = document.getElementById('refreshBtn');
        refreshBtn?.addEventListener('click', () => this.refreshInbox());
        
        // Modal controls
        const modalOverlay = document.getElementById('modalOverlay');
        const modalClose = document.getElementById('modalClose');
        const modalDelete = document.getElementById('modalDelete');
        const modalFullscreen = document.getElementById('modalFullscreen');

        modalOverlay?.addEventListener('click', (e) => {
            if (e.target === modalOverlay) this.closeModal();
        });
        modalClose?.addEventListener('click', () => this.closeModal());
        modalDelete?.addEventListener('click', () => {
            if (this.currentEmailData && this.currentEmailData.id) {
                this.deleteEmail(this.currentEmailData.id, true);
            }
        });
        modalFullscreen?.addEventListener('click', () => this.toggleFullscreen());

        // Headers toggle
        const toggleHeaders = document.getElementById('toggleHeaders');
        toggleHeaders?.addEventListener('click', () => this.toggleHeaders());

        const loadImagesBtn = document.getElementById('loadImagesBtn');
        loadImagesBtn?.addEventListener('click', () => {
            if (this.currentRenderData) {
                this.renderEmailFrame(this.currentRenderData, true);
                loadImagesBtn.hidden = true;
            }
        });

        // Copy current address
        const copyAddressBtn = document.getElementById('copyAddressBtn');
        copyAddressBtn?.addEventListener('click', () => this.copyAddress());

        // Random address generators
        const diceBtn = document.getElementById('diceBtn');
        diceBtn?.addEventListener('click', () => {
            const input = document.getElementById('emailPrefix');
            if (input) {
                input.value = this.randomPrefix();
                input.dispatchEvent(new Event('input'));
                input.focus();
            }
        });
        const switcherDiceBtn = document.getElementById('switcherDiceBtn');
        switcherDiceBtn?.addEventListener('click', () => {
            const input = document.getElementById('emailSwitcher');
            if (input) {
                input.value = this.randomPrefix();
                input.dispatchEvent(new Event('input'));
                input.focus();
            }
        });

        // Delete confirmation dialog
        const confirmOverlay = document.getElementById('confirmOverlay');
        const confirmCancel = document.getElementById('confirmCancel');
        const confirmOk = document.getElementById('confirmOk');
        confirmCancel?.addEventListener('click', () => this.resolveConfirm(false));
        confirmOk?.addEventListener('click', () => this.resolveConfirm(true));
        confirmOverlay?.addEventListener('click', (e) => {
            if (e.target === confirmOverlay) this.resolveConfirm(false);
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (this.confirmResolver) {
                    this.resolveConfirm(false);
                } else {
                    this.closeModal();
                }
            }
            if (e.key === 'r' && e.ctrlKey) {
                e.preventDefault();
                this.refreshInbox();
            }
        });
        
        // Page visibility change (pause/resume polling)
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopPolling();
            } else if (this.currentEmail) {
                this.startPolling();
            }
        });
    }
    
    setDomain() {
        const domainElement = document.getElementById('domainName');
        const switcherDomainElement = document.getElementById('switcherDomainName');
        if (domainElement) {
            domainElement.textContent = this.domain;
            if (switcherDomainElement) {
                switcherDomainElement.textContent = this.domain;
            }
        }
    }
    
    // Go back to homepage
    goHome() {
        // Stop polling
        this.stopPolling();
        this.stopTtl();

        // Clear stored email
        this.clearStoredEmail();
        
        // Clear delete tokens cache
        this.deleteTokens.clear();
        
        // Reset UI
        const emailCreator = document.getElementById('emailCreator');
        const inboxSection = document.getElementById('inboxSection');
        const emailInput = document.getElementById('emailPrefix');
        
        if (emailCreator) emailCreator.style.display = 'flex';
        if (inboxSection) inboxSection.style.display = 'none';
        if (emailInput) {
            emailInput.value = '';
            emailInput.focus();
        }
        const createBtn = document.getElementById('createBtn');
        if (createBtn) createBtn.disabled = true;
        
        this.currentEmail = null;
        this.lastEmailCount = 0;
        this.failedAttempts = 0;
        
        // Show toast
        this.showToast('Returned to homepage', 'success');
    }
    
    // Security: Enhanced input validation
    validateInput(event) {
        const input = event.target;
        const value = input.value;
        
        // Remove invalid characters and normalize
        let cleaned = value.replace(/[^a-zA-Z0-9._-]/g, '');
        
        // Prevent consecutive dots
        cleaned = cleaned.replace(/\.{2,}/g, '.');
        
        // Prevent leading/trailing dots
        cleaned = cleaned.replace(/^\.+|\.+$/g, '');
        
        // Unicode normalization
        cleaned = cleaned.normalize('NFC');
        
        if (cleaned !== value) {
            input.value = cleaned;
            this.showToast('Only letters, numbers, dots, hyphens, and underscores allowed', 'error');
        }
        
        // Length validation
        if (cleaned.length > 50) {
            input.value = cleaned.substring(0, 50);
            this.showToast('Email prefix too long (max 50 characters)', 'error');
        }
        
        // Visual feedback for create button
        if (input.id === 'emailPrefix') {
            const createBtn = document.getElementById('createBtn');
            if (createBtn) {
                createBtn.disabled = cleaned.length < 1;
            }
        }
    }
    
    // Security: Enhanced email validation
    isValidEmail(email) {
        const emailRegex = /^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,48}[a-zA-Z0-9])?@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/;
        
        // Basic regex check
        if (!emailRegex.test(email.toLowerCase()) || email.length > 100) {
            return false;
        }
        
        // Check for consecutive dots
        if (email.includes('..')) {
            return false;
        }
        
        // Unicode normalization check
        const normalized = email.normalize('NFC');
        if (normalized !== email) {
            return false;
        }
        
        return true;
    }
    
    // Security: Enhanced text sanitization
    sanitizeText(text) {
        if (!text) return '';
        
        // Create a temporary element to convert HTML entities
        const temp = document.createElement('div');
        temp.textContent = text;
        
        // Get the sanitized text and normalize
        let sanitized = temp.innerHTML;
        sanitized = sanitized.normalize('NFC');
        
        return sanitized;
    }
    
    // Security: HTML sanitization using DOMPurify
    // Keeps <style> tags for proper email rendering, displayed in sandboxed iframe
    sanitizeHtml(html) {
        if (!html) return '';

        // Use DOMPurify for battle-tested XSS prevention
        // - ADD_TAGS: ['style'] keeps CSS styling for proper email rendering
        // - Content is displayed in sandboxed iframe for extra security
        return DOMPurify.sanitize(html, {
            WHOLE_DOCUMENT: true,                   // Keep <head>, where email <style> lives
            ADD_TAGS: ['style'],                    // Keep style tags for email CSS
            FORBID_TAGS: [
                'script', 'iframe', 'frame', 'frameset',
                'object', 'embed', 'applet', 'form',
                'input', 'button', 'select', 'textarea',
                'link', 'meta', 'base'
            ],
            FORBID_ATTR: [
                'onerror', 'onload', 'onclick', 'onmouseover',
                'onfocus', 'onblur', 'onchange', 'onsubmit'
            ],
            ALLOW_DATA_ATTR: false,                 // No data-* attributes
            ALLOW_ARIA_ATTR: true,                  // Keep accessibility attributes
            KEEP_CONTENT: true                      // Keep text content when removing tags
        });
    }

    // Replace every color token inside a CSS value, keeping everything else
    // as written by the sender. url(...) spans and quoted strings are copied
    // through untouched so color-looking words in file names survive.
    remapColorsInValue(value, role) {
        const R = window.EmailRemap;
        return value
            .split(/(url\(\s*[^)]*\)|"[^"]*"|'[^']*')/gi)
            .map((part) => {
                if (/^(url\(|"|')/i.test(part)) return part;
                return part.replace(/#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|\b[a-zA-Z]{3,20}\b/g, (token) => {
                    const color = R.parseColor(token);
                    return color ? R.formatColor(R.remapColor(color, role)) : token;
                });
            })
            .join('');
    }

    // A URL that reaches out to the network: absolute http(s) or
    // protocol-relative (//host/...), which resolves to https here.
    isRemoteUrl(url) {
        return /^(https?:)?\/\//i.test(String(url).trim());
    }

    roleForProperty(prop) {
        if (prop === 'color' || prop === 'text-decoration-color') return 'text';
        if (prop.indexOf('background') === 0) return 'background';
        if (prop.indexOf('border') === 0 || prop.indexOf('outline') === 0) return 'background';
        return null;
    }

    // Rewrite the color-bearing declarations of one CSSStyleDeclaration in place.
    remapStyleDeclaration(style, state) {
        const props = [];
        for (let i = 0; i < style.length; i++) props.push(style[i]);
        for (const prop of props) {
            let value = style.getPropertyValue(prop);
            const priority = style.getPropertyPriority(prop);
            let changed = false;
            if (!state.allowRemoteImages && /url\(\s*['"]?(https?:)?\/\//i.test(value)) {
                const before = value;
                value = value.replace(/url\(\s*['"]?(https?:)?\/\/[^)]*\)/gi, 'none');
                if (value !== before) {
                    state.blockedImages++;
                    changed = true;
                }
            }
            if (!state.alreadyDark) {
                const role = this.roleForProperty(prop);
                if (role) {
                    const remapped = this.remapColorsInValue(value, role);
                    if (remapped !== value) {
                        value = remapped;
                        changed = true;
                    }
                }
            }
            if (changed) style.setProperty(prop, value, priority);
        }
    }

    remapSheetRules(rules, state) {
        for (const rule of rules) {
            if (rule.style) this.remapStyleDeclaration(rule.style, state);
            if (rule.cssRules) this.remapSheetRules(rule.cssRules, state);
        }
    }

    // Text-level fallback for engines that do not populate CSSOM on a
    // detached document: transform each declaration's value in place.
    remapStylesheetText(cssText, state) {
        return String(cssText).replace(/([a-zA-Z-]+)\s*:\s*([^;{}]+)/g, (match, prop, value) => {
            let v = value;
            if (!state.allowRemoteImages && /url\(\s*['"]?(https?:)?\/\//i.test(v)) {
                const before = v;
                v = v.replace(/url\(\s*['"]?(https?:)?\/\/[^)]*\)/gi, 'none');
                if (v !== before) state.blockedImages++;
            }
            if (!state.alreadyDark) {
                const role = this.roleForProperty(prop.toLowerCase());
                if (role) v = this.remapColorsInValue(v, role);
            }
            return `${prop}: ${v}`;
        });
    }

    // Best-effort effective background of the email, for dark-mail detection:
    // body first, then the first few wrapper elements, else assume light.
    resolveBodyBackground(doc) {
        const R = window.EmailRemap;
        const candidates = [doc.body];
        let el = doc.body.firstElementChild;
        for (let depth = 0; el && depth < 4; depth++) {
            candidates.push(el);
            el = el.firstElementChild;
        }
        for (const node of candidates) {
            if (!node) continue;
            const raw = node.style && (node.style.getPropertyValue('background-color') || node.style.getPropertyValue('background'));
            const fromAttr = node.getAttribute && node.getAttribute('bgcolor');
            for (const source of [raw, fromAttr]) {
                if (!source) continue;
                const color = R.parseColor(source.trim().split(/\s+/)[0]) || R.parseColor(source.trim());
                if (color && color.a > 0) return color;
            }
        }
        return null;
    }

    // Sanitize, then adapt the email's own colors to the dark surface and
    // strip remote images. Returns { head, body, blockedImages }.
    transformEmailDocument(html, options) {
        const allowRemoteImages = !!(options && options.allowRemoteImages);
        const clean = this.sanitizeHtml(html);
        const doc = document.implementation.createHTMLDocument('email');
        doc.documentElement.innerHTML = clean;

        const background = this.resolveBodyBackground(doc);
        const state = {
            allowRemoteImages,
            alreadyDark: background ? window.EmailRemap.isDarkColor(background) : false,
            blockedImages: 0
        };

        // Legacy color attributes. These only understand hex/named colors,
        // so the remapped value is written as hex.
        const R = window.EmailRemap;
        const remapAttrColor = (value, role) => {
            const color = R.parseColor(String(value).trim());
            return color ? R.formatHexColor(R.remapColor(color, role)) : value;
        };
        if (!state.alreadyDark) {
            for (const el of doc.querySelectorAll('[bgcolor]')) {
                el.setAttribute('bgcolor', remapAttrColor(el.getAttribute('bgcolor'), 'background'));
            }
            // <font color="..."> (Outlook forward headers use this)
            for (const el of doc.querySelectorAll('font[color]')) {
                el.setAttribute('color', remapAttrColor(el.getAttribute('color'), 'text'));
            }
            for (const attr of ['text', 'link', 'alink', 'vlink']) {
                const value = doc.body.getAttribute(attr);
                if (value) doc.body.setAttribute(attr, remapAttrColor(value, 'text'));
            }
        }

        // Inline styles
        for (const el of doc.querySelectorAll('[style]')) {
            this.remapStyleDeclaration(el.style, state);
        }

        // <style> sheets. Chromium exposes CSSOM on a detached
        // createHTMLDocument; where it is not populated (other engines),
        // fall back to a per-declaration text transform of the same rules.
        const processedSheets = new Set();
        for (const sheet of doc.styleSheets) {
            try {
                this.remapSheetRules(sheet.cssRules, state);
                const rules = [];
                for (const rule of sheet.cssRules) rules.push(rule.cssText);
                if (sheet.ownerNode) {
                    sheet.ownerNode.textContent = rules.join('\n');
                    processedSheets.add(sheet.ownerNode);
                }
            } catch (err) {
                // Unreadable sheet: handled by the text fallback below
            }
        }
        for (const styleEl of doc.querySelectorAll('style')) {
            if (!processedSheets.has(styleEl)) {
                styleEl.textContent = this.remapStylesheetText(styleEl.textContent, state);
            }
        }

        // cid: images reference MIME attachments that are not stored;
        // show the placeholder instead of a broken icon + CSP error
        for (const img of doc.querySelectorAll('img')) {
            if (/^cid:/i.test((img.getAttribute('src') || '').trim())) {
                img.setAttribute('src', BLOCKED_IMAGE_PLACEHOLDER);
                img.style.setProperty('max-width', '160px');
            }
        }

        // Remote images: absolute and protocol-relative URLs, in src, srcset,
        // and legacy background attributes
        if (!allowRemoteImages) {
            for (const img of doc.querySelectorAll('img')) {
                const src = img.getAttribute('src') || '';
                const srcset = img.getAttribute('srcset') || '';
                const remoteSrc = this.isRemoteUrl(src);
                const remoteSrcset = srcset && /(^|[\s,])(https?:)?\/\//i.test(srcset);
                if (remoteSrc || remoteSrcset) {
                    state.blockedImages++;
                    img.setAttribute('src', BLOCKED_IMAGE_PLACEHOLDER);
                    img.style.setProperty('max-width', '160px');
                }
                // srcset can name remote candidates on its own; drop it always
                img.removeAttribute('srcset');
            }
            for (const el of doc.querySelectorAll('[background]')) {
                if (this.isRemoteUrl(el.getAttribute('background') || '')) {
                    state.blockedImages++;
                    el.removeAttribute('background');
                }
            }
        }

        // Body attributes (style, bgcolor, text...) survive into the wrapper
        let bodyAttrs = '';
        for (const attr of doc.body.attributes) {
            bodyAttrs += ` ${attr.name}="${attr.value.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"`;
        }

        return {
            head: doc.head.innerHTML,
            body: doc.body.innerHTML,
            bodyAttrs,
            blockedImages: state.blockedImages
        };
    }

    renderEmailFrame(emailData, allowRemoteImages) {
        const emailFrame = document.getElementById('emailFrame');
        const loadImagesBtn = document.getElementById('loadImagesBtn');
        if (!emailFrame) return;

        let content;
        let blockedImages = 0;

        if (emailData.isHtml) {
            const result = this.transformEmailDocument(emailData.content, { allowRemoteImages });
            blockedImages = result.blockedImages;
            content = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root { color-scheme: dark; }
        html, body {
            margin: 0;
            padding: 16px;
            background: #0c0f0b;
            color: #d8e2d4;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            word-wrap: break-word;
            -webkit-text-size-adjust: 100%;
        }
        a { color: #a3e635; }
        img { max-width: 100%; height: auto; }
        pre { white-space: pre-wrap; }
        /* Unstyled dividers get a subtle line instead of the UA's bright one */
        hr { border: none; border-top: 1px solid #3a4535; }
    </style>
    ${result.head}
</head>
<body${result.bodyAttrs}>${result.body}</body>
</html>`;
        } else {
            const escapedText = String(emailData.content)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            content = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: 'JetBrains Mono', ui-monospace, monospace;
            font-size: 14px;
            line-height: 1.6;
            color: #d8e2d4;
            background: #0c0f0b;
            margin: 0;
            padding: 16px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
    </style>
</head>
<body>${escapedText}</body>
</html>`;
        }

        emailFrame.srcdoc = content;
        // Safety net after the source-level remap: verify computed contrast
        // in the rendered document, catching any color vector the transform
        // did not recognize (system colors, unusual attributes, inheritance).
        emailFrame.onload = () => {
            try {
                this.guardFrameContrast(emailFrame.contentDocument);
            } catch (err) {
                // Guard is best-effort; the frame stays as transformed
            }
        };

        if (loadImagesBtn) {
            if (blockedImages > 0 && !allowRemoteImages) {
                loadImagesBtn.hidden = false;
                loadImagesBtn.textContent = blockedImages === 1 ? 'Load 1 image' : `Load ${blockedImages} images`;
            } else {
                loadImagesBtn.hidden = true;
            }
        }
    }

    // Walk the rendered email and fix any text whose computed color has no
    // contrast against its effective background. This is layout-aware (runs
    // in the live frame), so it catches everything the source transform
    // cannot see: system color keywords, inherited colors, odd attributes.
    guardFrameContrast(doc) {
        if (!doc || !doc.body || !window.EmailRemap) return;
        const R = window.EmailRemap;
        const win = doc.defaultView;
        const frameBg = R.parseColor('#0c0f0b');

        const effectiveBackground = (el) => {
            let node = el;
            while (node && node.nodeType === 1) {
                const bg = R.parseColor(win.getComputedStyle(node).backgroundColor);
                if (bg && bg.a > 0.1) return bg;
                node = node.parentElement;
            }
            return frameBg;
        };

        const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);
        const seen = new Set();
        let textNode;
        while ((textNode = walker.nextNode())) {
            if (!textNode.textContent.trim()) continue;
            const el = textNode.parentElement;
            if (!el || seen.has(el)) continue;
            seen.add(el);
            const color = R.parseColor(win.getComputedStyle(el).color);
            if (!color || color.a === 0) continue;
            const bg = effectiveBackground(el);
            if (Math.abs(color.l - bg.l) >= 0.3) continue;
            // Unreadable: push the text to the other side of its background,
            // keeping hue so colored text stays colored
            const fixedL = bg.l < 0.5 ? Math.max(0.78, 1 - color.l * 0.3) : Math.min(0.18, color.l * 0.3);
            el.style.setProperty(
                'color',
                R.formatColor({ h: color.h, s: Math.min(color.s, 0.85), l: fixedL, a: color.a }),
                'important'
            );
        }
    }

    // Copy the active address to the clipboard
    async copyAddress() {
        if (!this.currentEmail) return;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(this.currentEmail);
            } else {
                const temp = document.createElement('input');
                temp.value = this.currentEmail;
                document.body.appendChild(temp);
                temp.select();
                document.execCommand('copy');
                document.body.removeChild(temp);
            }
            this.showToast('Address copied.', 'success');
        } catch (error) {
            this.showToast('Copy failed. Select the address and copy it manually.', 'error');
        }
    }

    // Crypto-random adjective-noun prefix, e.g. midnight-fox42
    randomPrefix() {
        const adjectives = [
            'amber', 'ashen', 'bold', 'brisk', 'broad', 'calm', 'cedar', 'clear',
            'cobalt', 'copper', 'coral', 'crisp', 'dusty', 'early', 'ember', 'faded',
            'feral', 'flint', 'frost', 'gentle', 'gray', 'green', 'hazel', 'hidden',
            'hollow', 'iron', 'ivory', 'jade', 'keen', 'late', 'lone', 'lucid',
            'midnight', 'misty', 'noble', 'north', 'olive', 'pale', 'quiet', 'rapid',
            'rustic', 'silent', 'slate', 'solar', 'still', 'stone', 'swift', 'wild'
        ];
        const nouns = [
            'aspen', 'badger', 'birch', 'bison', 'cedar', 'comet', 'crane', 'creek',
            'crow', 'delta', 'drift', 'eagle', 'ember', 'falcon', 'fern', 'finch',
            'fox', 'gorge', 'hare', 'hawk', 'heron', 'lark', 'lynx', 'maple',
            'marsh', 'moth', 'otter', 'owl', 'pike', 'pine', 'raven', 'reef',
            'ridge', 'river', 'sable', 'shard', 'spruce', 'stag', 'stork', 'summit',
            'swan', 'thorn', 'tide', 'trail', 'vale', 'wolf', 'wren', 'yarrow'
        ];
        const random = new Uint32Array(3);
        crypto.getRandomValues(random);
        const adjective = adjectives[random[0] % adjectives.length];
        const noun = nouns[random[1] % nouns.length];
        const digits = String(random[2] % 100).padStart(2, '0');
        return `${adjective}-${noun}${digits}`;
    }

    // Promise-based replacement for window.confirm()
    confirmDialog(message) {
        const overlay = document.getElementById('confirmOverlay');
        const text = document.getElementById('confirmText');
        const cancelBtn = document.getElementById('confirmCancel');
        if (!overlay || !text) {
            return Promise.resolve(window.confirm(message));
        }
        text.textContent = message;
        overlay.hidden = false;
        this.confirmReturnFocus = document.activeElement;
        if (cancelBtn) cancelBtn.focus();
        return new Promise((resolve) => {
            this.confirmResolver = resolve;
        });
    }

    resolveConfirm(result) {
        const overlay = document.getElementById('confirmOverlay');
        if (overlay) overlay.hidden = true;
        if (this.confirmReturnFocus && this.confirmReturnFocus.focus) {
            this.confirmReturnFocus.focus();
        }
        this.confirmReturnFocus = null;
        if (this.confirmResolver) {
            const resolve = this.confirmResolver;
            this.confirmResolver = null;
            resolve(result);
        }
    }

    // TTL countdown chip; hidden when the server does not report expires_at
    updateTtl(expiresAt) {
        const chip = document.getElementById('ttlChip');
        if (!chip) return;
        if (!expiresAt) {
            if (!this.inboxExpiresAt) chip.hidden = true;
            return;
        }
        const parsed = Date.parse(expiresAt);
        if (Number.isNaN(parsed)) return;
        this.inboxExpiresAt = parsed;
        chip.hidden = false;
        this.renderTtl();
        if (!this.ttlTimer) {
            this.ttlTimer = setInterval(() => {
                if (document.hidden) return;
                this.renderTtl();
            }, 1000);
        }
    }

    renderTtl() {
        const chip = document.getElementById('ttlChip');
        if (!chip || !this.inboxExpiresAt) return;
        let remaining = Math.floor((this.inboxExpiresAt - Date.now()) / 1000);
        if (remaining <= 0) {
            chip.textContent = 'Expired';
            chip.classList.add('ttl-warning');
            return;
        }
        const hours = String(Math.floor(remaining / 3600)).padStart(2, '0');
        const minutes = String(Math.floor((remaining % 3600) / 60)).padStart(2, '0');
        const seconds = String(remaining % 60).padStart(2, '0');
        chip.textContent = `Self-destructs in ${hours}:${minutes}:${seconds}`;
        chip.classList.toggle('ttl-warning', remaining < 3600);
    }

    stopTtl() {
        if (this.ttlTimer) {
            clearInterval(this.ttlTimer);
            this.ttlTimer = null;
        }
        this.inboxExpiresAt = null;
        const chip = document.getElementById('ttlChip');
        if (chip) {
            chip.hidden = true;
            chip.classList.remove('ttl-warning');
        }
    }

    async createEmail() {
        const input = document.getElementById('emailPrefix');
        const prefix = input?.value?.trim();

        if (!prefix) {
            this.showToast('Please enter an email prefix', 'error');
            input?.focus();
            return;
        }

        // Security: Enhanced validation
        if (!/^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,48}[a-zA-Z0-9])?$/.test(prefix)) {
            this.showToast('Invalid email prefix format', 'error');
            input?.focus();
            return;
        }

        if (prefix.includes('..')) {
            this.showToast('Consecutive dots not allowed', 'error');
            input?.focus();
            return;
        }
        
        // Normalize email to lowercase
        const email = `${prefix}@${this.domain}`.toLowerCase();
        
        // Verify it's a valid email
        if (!this.isValidEmail(email)) {
            this.showToast('Invalid email format', 'error');
            return;
        }
        
        // Try to create inbox - API will return 409 if it already exists
        try {
            const response = await fetch('/api/inbox/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({ email })
            });
            
            if (!response.ok && response.status !== 409) {
                // If CSRF token expired, refresh it and retry
                if (response.status === 403) {
                    await this.getCSRFToken();
                    const retryResponse = await fetch('/api/inbox/create', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': this.csrfToken
                        },
                        body: JSON.stringify({ email })
                    });
                    
                    if (!retryResponse.ok && retryResponse.status !== 409) {
                        throw new Error('Failed to create inbox');
                    }
                } else {
                    throw new Error('Failed to create inbox');
                }
            }
        } catch (error) {
            // Continue anyway - inbox will be created when first email arrives
            console.warn('Inbox creation failed, will be created on first email');
        }
        
        // Show inbox immediately
        this.showInbox(email);
        this.showToast('Inbox ready. Mail shows up within seconds.', 'success');
        
        // Store in sessionStorage for session persistence
        this.storeEmail(email);
    }
    
    async switchEmail() {
        const input = document.getElementById('emailSwitcher');
        const prefix = input?.value?.trim();
        
        if (!prefix) {
            this.showToast('Please enter an email prefix', 'error');
            input?.focus();
            return;
        }
        
        // Security: Enhanced validation
        if (!/^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,48}[a-zA-Z0-9])?$/.test(prefix)) {
            this.showToast('Invalid email prefix format', 'error');
            input?.focus();
            return;
        }

        if (prefix.includes('..')) {
            this.showToast('Consecutive dots not allowed', 'error');
            input?.focus();
            return;
        }

        // Normalize email to lowercase
        const email = `${prefix}@${this.domain}`.toLowerCase();

        // Verify it's a valid email
        if (!this.isValidEmail(email)) {
            this.showToast('Invalid email format', 'error');
            return;
        }

        // Check if it's the same email (case-insensitive)
        if (email === this.currentEmail?.toLowerCase()) {
            this.showToast('Already viewing this inbox', 'error');
            return;
        }

        // Reset the countdown; the new inbox reports its own expiry
        this.stopTtl();

        // Try to create the inbox first (just like createEmail does)
        try {
            const response = await fetch('/api/inbox/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({ email })
            });
            
            if (!response.ok && response.status !== 409) {
                // If CSRF token expired, refresh it and retry
                if (response.status === 403) {
                    await this.getCSRFToken();
                    const retryResponse = await fetch('/api/inbox/create', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': this.csrfToken
                        },
                        body: JSON.stringify({ email })
                    });
                    
                    if (!retryResponse.ok && retryResponse.status !== 409) {
                        throw new Error('Failed to create inbox');
                    }
                } else {
                    throw new Error('Failed to create inbox');
                }
            }
        } catch (error) {
            // Continue anyway - inbox will be created when first email arrives
            console.warn('Inbox creation failed, will be created on first email');
        }
        
        // Clear current email data and tokens
        this.lastEmailCount = 0;
        this.deleteTokens.clear();
        this.failedAttempts = 0;
        
        // Switch to new email
        this.currentEmail = email;
        this.storeEmail(email);
        
        // Update status
        this.updateStatus('Switching inbox...');
        
        // Clear email list immediately for better UX
        const emailList = document.getElementById('emailList');
        if (emailList) {
            const existingItems = emailList.querySelectorAll('.email-item');
            existingItems.forEach(item => item.remove());
        }
        
        // Load emails for new inbox
        this.loadEmails();
        
        this.showToast('Switched to ' + email, 'success');
    }
    
    showInbox(email) {
        this.currentEmail = email;
        this.failedAttempts = 0;
        
        // Update UI
        const emailCreator = document.getElementById('emailCreator');
        const inboxSection = document.getElementById('inboxSection');
        const switcherInput = document.getElementById('emailSwitcher');
        
        if (emailCreator) emailCreator.style.display = 'none';
        if (inboxSection) inboxSection.style.display = 'flex';
        
        // Set the current email in the switcher input (just the prefix)
        if (switcherInput) {
            const prefix = email.split('@')[0];
            switcherInput.value = prefix;
        }
        
        // Update status
        this.updateStatus('Active - Waiting for emails...');
        
        // Start polling for emails
        this.startPolling();
        
        // Initial load
        this.loadEmails();
    }
    
    async loadEmails() {
        if (!this.currentEmail) return;
        
        const prefix = this.currentEmail.split('@')[0];
        
        try {
            // Add cache-busting parameter
            const response = await fetch(`/api/inbox/${prefix}.json?t=${Date.now()}`, {
                method: 'GET',
                headers: {
                    'Cache-Control': 'no-cache'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayEmails(data.emails || []);
                this.updateEmailCount(data.count || 0);
                this.updateTtl(data.expires_at);

                // Pre-fetch delete tokens for new emails
                if (data.emails && data.emails.length > 0) {
                    this.prefetchDeleteTokens(data.emails);
                }
                
                // Update status based on activity
                if (data.emails && data.emails.length > 0) {
                    this.updateStatus(`${data.emails.length} email(s) received`);
                } else {
                    this.updateStatus('Active - Waiting for emails...');
                }
                
                // Reset failed attempts on success
                this.failedAttempts = 0;
            } else if (response.status === 404) {
                // Inbox doesn't exist yet, show empty state
                this.displayEmails([]);
                this.updateEmailCount(0);
                this.updateStatus('Active - Waiting for emails...');
            } else {
                this.failedAttempts++;
                if (this.failedAttempts >= this.maxFailedAttempts) {
                    this.stopPolling();
                    this.updateStatus('Connection lost - please refresh');
                    this.showToast('Connection issues detected. Please refresh the page.', 'error');
                }
            }
        } catch (error) {
            this.failedAttempts++;
            if (this.failedAttempts >= this.maxFailedAttempts) {
                this.stopPolling();
                this.updateStatus('Connection lost - please refresh');
            }
        }
    }
    
    // Pre-fetch delete tokens for performance
    async prefetchDeleteTokens(emails) {
        const prefix = this.currentEmail.split('@')[0];
        
        for (const email of emails) {
            if (!this.deleteTokens.has(email.id)) {
                try {
                    const response = await fetch('/api/token/generate', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': this.csrfToken
                        },
                        body: JSON.stringify({ prefix, emailId: email.id })
                    });
                    
                    if (response.ok) {
                        const { token } = await response.json();
                        this.deleteTokens.set(email.id, token);
                    } else if (response.status === 403) {
                        // CSRF token expired, refresh and retry
                        await this.getCSRFToken();
                        const retryResponse = await fetch('/api/token/generate', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': this.csrfToken
                            },
                            body: JSON.stringify({ prefix, emailId: email.id })
                        });
                        
                        if (retryResponse.ok) {
                            const { token } = await retryResponse.json();
                            this.deleteTokens.set(email.id, token);
                        }
                    }
                } catch (error) {
                    // Silently fail - will retry when delete is attempted
                }
            }
        }
    }
    
    displayEmails(emails) {
        const emailList = document.getElementById('emailList');
        const emptyState = document.getElementById('emptyState');
        
        if (!emailList) return;
        
        if (!emails || emails.length === 0) {
            if (emptyState) emptyState.style.display = 'block';
            // Clear any existing email items
            const existingItems = emailList.querySelectorAll('.email-item');
            existingItems.forEach(item => item.remove());
            return;
        }
        
        if (emptyState) emptyState.style.display = 'none';
        
        // Clear existing emails
        const existingItems = emailList.querySelectorAll('.email-item');
        existingItems.forEach(item => item.remove());
        
        // Add new emails
        emails.forEach(email => {
            const emailElement = this.createEmailElement(email);
            emailList.appendChild(emailElement);
        });
    }
    
    createEmailElement(email) {
        const div = document.createElement('div');
        div.className = 'email-item';
        div.setAttribute('data-email-id', email.id);

        const timeAgo = this.formatTimeAgo(email.receivedAt);
        const sender = this.sanitizeText(email.sender || 'Unknown sender');
        const senderName = email.senderName ? this.sanitizeText(email.senderName) : sender;
        const subject = this.sanitizeText(email.subject || '(No subject)');

        div.innerHTML = `
            <div class="email-content-wrapper" data-email-id="${email.id}">
                <div class="email-info">
                    <div class="email-sender">${senderName}</div>
                    <div class="email-subject">${subject}</div>
                </div>
                <div class="email-meta">
                    <span class="email-time">${timeAgo}</span>
                    <span class="email-size">${this.formatBytes(email.size || 0)}</span>
                </div>
            </div>
            <button class="delete-btn" title="Delete email" data-email-id="${email.id}" aria-label="Delete email">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 7 h16"></path><path d="M9 7 V5 a1 1 0 0 1 1 -1 h4 a1 1 0 0 1 1 1 v2"></path><path d="M6 7 l1 13 a1 1 0 0 0 1 1 h8 a1 1 0 0 0 1 -1 l1 -13"></path></svg>
            </button>
        `;
        
        // Click on email content to view
        const contentWrapper = div.querySelector('.email-content-wrapper');
        contentWrapper.addEventListener('click', () => this.showEmailDetail(email));
        
        // Click on delete button
        const deleteBtn = div.querySelector('.delete-btn');
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.deleteEmail(email.id);
        });
        
        return div;
    }
    
    showEmailDetail(email) {
        // Store current email data for headers
        this.currentEmailData = email;
        
        const emailData = {
            sender: email.sender || 'Unknown sender',
            senderName: email.senderName,
            subject: email.subject || '(No subject)',
            time: this.formatTimeAgo(email.receivedAt),
            // Prefer HTML content over plain text for display
            content: email.bodyHtml || email.bodyText || 'No content available',
            isHtml: !!email.bodyHtml,
            messageId: email.messageId,
            receivedAt: email.receivedAt,
            size: email.size,
            spfResult: email.spfResult,
            dkimResult: email.dkimResult
        };
        
        this.openModal(emailData);
    }
    
    openModal(emailData) {
        const modalOverlay = document.getElementById('modalOverlay');
        const modalSubject = document.getElementById('modalSubject');
        const modalSender = document.getElementById('modalSender');
        const modalTime = document.getElementById('modalTime');
        const emailFrame = document.getElementById('emailFrame');
        const toggleText = document.getElementById('toggleText');
        const emailHeaders = document.getElementById('emailHeaders');
        const emailModal = document.getElementById('emailModal');

        if (modalSubject) modalSubject.textContent = emailData.subject;
        if (modalSender) modalSender.textContent = emailData.senderName || emailData.sender;
        if (modalTime) modalTime.textContent = emailData.time;

        // Display email content in sandboxed iframe for security.
        // Remote images stay blocked until the reader asks for them.
        this.currentRenderData = emailData;
        this.renderEmailFrame(emailData, false);

        // Reset headers display
        if (toggleText) toggleText.textContent = 'Show Headers';
        if (emailHeaders) {
            emailHeaders.style.display = 'none';
            emailHeaders.innerHTML = '';
        }

        // Reset fullscreen state
        if (emailModal) {
            emailModal.classList.remove('modal-fullscreen');
        }
        const fullscreenBtn = document.getElementById('modalFullscreen');
        if (fullscreenBtn) {
            const expandIcon = fullscreenBtn.querySelector('.icon-expand');
            const compressIcon = fullscreenBtn.querySelector('.icon-compress');
            if (expandIcon) expandIcon.style.display = '';
            if (compressIcon) compressIcon.style.display = 'none';
            fullscreenBtn.title = 'Toggle fullscreen';
        }

        if (modalOverlay) {
            modalOverlay.style.display = 'flex';
            document.body.style.overflow = 'hidden';
            document.body.classList.add('modal-open');
        }
    }

    closeModal() {
        const modalOverlay = document.getElementById('modalOverlay');
        const emailFrame = document.getElementById('emailFrame');
        const emailModal = document.getElementById('emailModal');

        if (modalOverlay) {
            modalOverlay.style.display = 'none';
            document.body.style.overflow = 'auto';
            document.body.classList.remove('modal-open');
        }

        // Clear iframe content
        if (emailFrame) {
            emailFrame.srcdoc = '';
        }

        // Reset fullscreen
        if (emailModal) {
            emailModal.classList.remove('modal-fullscreen');
        }

        // Clear current email data
        this.currentEmailData = null;
    }

    toggleFullscreen() {
        const emailModal = document.getElementById('emailModal');
        const fullscreenBtn = document.getElementById('modalFullscreen');

        if (emailModal) {
            emailModal.classList.toggle('modal-fullscreen');

            // Update button icon
            if (fullscreenBtn) {
                const fullscreen = emailModal.classList.contains('modal-fullscreen');
                const expandIcon = fullscreenBtn.querySelector('.icon-expand');
                const compressIcon = fullscreenBtn.querySelector('.icon-compress');
                if (expandIcon) expandIcon.style.display = fullscreen ? 'none' : '';
                if (compressIcon) compressIcon.style.display = fullscreen ? '' : 'none';
                fullscreenBtn.title = fullscreen ? 'Exit fullscreen' : 'Toggle fullscreen';
            }
        }
    }
    
    toggleHeaders() {
        const emailHeaders = document.getElementById('emailHeaders');
        const toggleText = document.getElementById('toggleText');
        
        if (!emailHeaders || !this.currentEmailData) return;
        
        if (emailHeaders.style.display === 'none') {
            // Show headers
            emailHeaders.style.display = 'block';
            if (toggleText) toggleText.textContent = 'Hide Headers';
            
            // Format and display headers
            const headers = this.formatEmailHeaders(this.currentEmailData);
            emailHeaders.innerHTML = headers;
        } else {
            // Hide headers
            emailHeaders.style.display = 'none';
            if (toggleText) toggleText.textContent = 'Show Headers';
        }
    }
    
    formatEmailHeaders(email) {
        const headers = [];
        
        // From header with full email
        headers.push(`<div class="header-line"><span class="header-label">From:</span> ${this.sanitizeText(email.senderName || '')} &lt;${this.sanitizeText(email.sender)}&gt;</div>`);
        
        // To header
        headers.push(`<div class="header-line"><span class="header-label">To:</span> ${this.sanitizeText(this.currentEmail)}</div>`);
        
        // Subject
        headers.push(`<div class="header-line"><span class="header-label">Subject:</span> ${this.sanitizeText(email.subject || '(No subject)')}</div>`);
        
        // Date
        const date = new Date(email.receivedAt * 1000);
        headers.push(`<div class="header-line"><span class="header-label">Date:</span> ${date.toUTCString()}</div>`);
        
        // Message-ID
        if (email.messageId) {
            headers.push(`<div class="header-line"><span class="header-label">Message-ID:</span> ${this.sanitizeText(email.messageId)}</div>`);
        }
        
        // SPF Result
        if (email.spfResult && email.spfResult !== 'none') {
            const spfStatus = email.spfResult.toLowerCase();
            const spfClass = spfStatus === 'pass' ? 'header-pass' : spfStatus === 'fail' ? 'header-fail' : 'header-neutral';
            headers.push(`<div class="header-line"><span class="header-label">SPF:</span> <span class="${spfClass}">${this.sanitizeText(email.spfResult)}</span></div>`);
        }
        
        // DKIM Result
        if (email.dkimResult && email.dkimResult !== 'none') {
            const dkimStatus = email.dkimResult.toLowerCase();
            const dkimClass = dkimStatus === 'pass' ? 'header-pass' : dkimStatus === 'fail' ? 'header-fail' : 'header-neutral';
            headers.push(`<div class="header-line"><span class="header-label">DKIM:</span> <span class="${dkimClass}">${this.sanitizeText(email.dkimResult)}</span></div>`);
        }
        
        // Size
        headers.push(`<div class="header-line"><span class="header-label">Size:</span> ${this.formatBytes(email.size || 0)}</div>`);
        
        // Content type
        if (email.bodyHtml && email.bodyText) {
            headers.push(`<div class="header-line"><span class="header-label">Content-Type:</span> multipart/alternative</div>`);
        } else if (email.bodyHtml) {
            headers.push(`<div class="header-line"><span class="header-label">Content-Type:</span> text/html</div>`);
        } else {
            headers.push(`<div class="header-line"><span class="header-label">Content-Type:</span> text/plain</div>`);
        }
        
        return headers.join('');
    }
    
    refreshInbox() {
        if (this.currentEmail) {
            this.loadEmails();
            this.showToast('Inbox refreshed', 'success');
        }
    }
    
    startPolling() {
        this.stopPolling(); // Clear any existing interval
        
        this.pollInterval = setInterval(() => {
            if (this.currentEmail && !document.hidden) {
                this.loadEmails();
            }
        }, this.pollRate);
    }
    
    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }
    
    updateEmailCount(count) {
        const emailCountElement = document.getElementById('emailCount');
        if (emailCountElement) {
            emailCountElement.textContent = count;
            
            // Animation for new emails
            if (count > this.lastEmailCount && this.lastEmailCount > 0) {
                emailCountElement.style.animation = 'none';
                setTimeout(() => {
                    emailCountElement.style.animation = 'pulse 0.5s ease-in-out';
                }, 10);
                
                // Show notification for new emails
                const newCount = count - this.lastEmailCount;
                this.showToast(`${newCount} new email${newCount > 1 ? 's' : ''} received! 📧`, 'success');
            }
        }
        
        this.lastEmailCount = count;
    }
    
    updateStatus(text) {
        const statusText = document.getElementById('statusText');
        if (statusText) {
            statusText.textContent = text;
        }
    }
    
    showToast(message, type = 'success') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        // Auto remove after 3 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.style.animation = 'slideInRight 0.3s ease-out reverse';
                setTimeout(() => {
                    container.removeChild(toast);
                }, 300);
            }
        }, 3000);
    }
    
    // Utility functions
    formatTimeAgo(timestamp) {
        const now = Date.now() / 1000;
        const diff = now - timestamp;
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }
    
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
    
    // Local storage helpers with try-catch for private browsing
    storeEmail(email) {
        try {
            sessionStorage.setItem('spameater_email', email);
        } catch (error) {
            // Silently fail - not critical
        }
    }
    
    getStoredEmail() {
        try {
            return sessionStorage.getItem('spameater_email');
        } catch (error) {
            return null;
        }
    }
    
    clearStoredEmail() {
        try {
            sessionStorage.removeItem('spameater_email');
        } catch (error) {
            // Silently fail - not critical
        }
    }
    
    // Delete email function with token authentication
    async deleteEmail(emailId, fromModal = false) {
        if (!this.currentEmail) return;
        
        // Show confirmation
        const confirmDelete = await this.confirmDialog('Delete this email? It cannot be recovered.');
        if (!confirmDelete) return;
        
        // If deleting from modal, close it first
        if (fromModal) {
            this.closeModal();
        }
        
        const prefix = this.currentEmail.split('@')[0];
        
        try {
            // Get delete token
            let token = this.deleteTokens.get(emailId);
            
            // If no cached token, fetch one
            if (!token) {
                const tokenResponse = await fetch('/api/token/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': this.csrfToken
                    },
                    body: JSON.stringify({ prefix, emailId })
                });
                
                if (!tokenResponse.ok) {
                    if (tokenResponse.status === 403) {
                        // CSRF token expired, refresh and retry
                        await this.getCSRFToken();
                        const retryResponse = await fetch('/api/token/generate', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': this.csrfToken
                            },
                            body: JSON.stringify({ prefix, emailId })
                        });
                        
                        if (!retryResponse.ok) {
                            throw new Error('Failed to get delete token');
                        }
                        
                        const tokenData = await retryResponse.json();
                        token = tokenData.token;
                    } else {
                        throw new Error('Failed to get delete token');
                    }
                } else {
                    const tokenData = await tokenResponse.json();
                    token = tokenData.token;
                }
                
                this.deleteTokens.set(emailId, token);
            }
            
            // Call the delete API endpoint with token
            const deleteResponse = await fetch(`/api/delete/${prefix}/${emailId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Delete-Token': token,
                    'X-CSRF-Token': this.csrfToken
                }
            });
            
            if (deleteResponse.ok) {
                // Successfully deleted on server
                const result = await deleteResponse.json();
                
                // Remove token from cache
                this.deleteTokens.delete(emailId);
                
                // Update the display immediately
                const emailList = document.getElementById('emailList');
                if (emailList) {
                    const emailElement = emailList.querySelector(`[data-email-id="${emailId}"]`);
                    if (emailElement) {
                        emailElement.style.animation = 'fadeOut 0.3s ease-out';
                        setTimeout(() => {
                            emailElement.remove();
                            
                            // Check if inbox is now empty
                            const remainingEmails = emailList.querySelectorAll('.email-item');
                            if (remainingEmails.length === 0) {
                                const emptyState = document.getElementById('emptyState');
                                if (emptyState) emptyState.style.display = 'block';
                                this.updateStatus('Active - Waiting for emails...');
                            }
                        }, 300);
                    }
                }
                
                // Update count
                this.updateEmailCount(result.remaining || 0);
                
                // Show success message
                this.showToast('Email deleted permanently', 'success');
                
            } else if (deleteResponse.status === 403) {
                // CSRF token expired during delete
                await this.getCSRFToken();
                // Retry delete with new CSRF token
                const retryDeleteResponse = await fetch(`/api/delete/${prefix}/${emailId}`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Delete-Token': token,
                        'X-CSRF-Token': this.csrfToken
                    }
                });
                
                if (retryDeleteResponse.ok) {
                    // Handle successful delete (same as above)
                    const result = await retryDeleteResponse.json();
                    this.deleteTokens.delete(emailId);
                    
                    const emailList = document.getElementById('emailList');
                    if (emailList) {
                        const emailElement = emailList.querySelector(`[data-email-id="${emailId}"]`);
                        if (emailElement) {
                            emailElement.style.animation = 'fadeOut 0.3s ease-out';
                            setTimeout(() => {
                                emailElement.remove();
                                const remainingEmails = emailList.querySelectorAll('.email-item');
                                if (remainingEmails.length === 0) {
                                    const emptyState = document.getElementById('emptyState');
                                    if (emptyState) emptyState.style.display = 'block';
                                    this.updateStatus('Active - Waiting for emails...');
                                }
                            }, 300);
                        }
                    }
                    
                    this.updateEmailCount(result.remaining || 0);
                    this.showToast('Email deleted permanently', 'success');
                } else {
                    throw new Error('Failed to delete email');
                }
            } else {
                throw new Error('Failed to delete email');
            }
        } catch (error) {
            this.showToast('Failed to delete email', 'error');
            
            // Reload emails to sync with server
            this.loadEmails();
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Create global instance for debugging
    window.spamEater = new SpamEater();
});
