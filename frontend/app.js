// SpamEater Frontend Application - Security Enhanced
// Secure, minimal JavaScript for email management

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
        
        modalOverlay?.addEventListener('click', (e) => {
            if (e.target === modalOverlay) this.closeModal();
        });
        modalClose?.addEventListener('click', () => this.closeModal());
        modalDelete?.addEventListener('click', () => {
            if (this.currentEmailData && this.currentEmailData.id) {
                this.deleteEmail(this.currentEmailData.id, true);
            }
        });
        
        // Headers toggle
        const toggleHeaders = document.getElementById('toggleHeaders');
        toggleHeaders?.addEventListener('click', () => this.toggleHeaders());
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeModal();
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
    
    // Security: Enhanced HTML sanitization to prevent XSS
    sanitizeHtml(html) {
        if (!html) return '';
        
        // Create a temporary element to parse HTML
        const temp = document.createElement('div');
        temp.innerHTML = html;
        
        // Remove all script tags
        const scripts = temp.querySelectorAll('script');
        scripts.forEach(script => script.remove());
        
        // Remove all elements with event handlers
        const allElements = temp.querySelectorAll('*');
        allElements.forEach(el => {
            // Remove all event attributes
            for (let attr of Array.from(el.attributes)) {
                if (attr.name.startsWith('on') || attr.name === 'href' && attr.value.startsWith('javascript:')) {
                    el.removeAttribute(attr.name);
                }
            }
            
            // Remove javascript: URLs
            if (el.href && el.href.startsWith('javascript:')) {
                el.removeAttribute('href');
            }
            if (el.src && el.src.startsWith('javascript:')) {
                el.removeAttribute('src');
            }
            
            // Remove data: URLs from images (prevent tracking pixels)
            if (el.tagName === 'IMG' && el.src && el.src.startsWith('data:')) {
                el.removeAttribute('src');
                el.setAttribute('alt', '[Image removed for security]');
            }
        });
        
        // Remove dangerous tags
        const dangerousTags = ['iframe', 'object', 'embed', 'link', 'meta', 'style', 'base', 'form'];
        dangerousTags.forEach(tag => {
            const elements = temp.querySelectorAll(tag);
            elements.forEach(el => el.remove());
        });
        
        // Remove SVG with scripts
        const svgs = temp.querySelectorAll('svg');
        svgs.forEach(svg => {
            if (svg.innerHTML.includes('script') || svg.innerHTML.includes('onload')) {
                svg.remove();
            }
        });
        
        return temp.innerHTML;
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
        this.showToast('Email created successfully! 🍽️', 'success');
        
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
        
        // NEW: Try to create the inbox first (just like createEmail does)
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
                <div class="email-sender">${senderName}</div>
                <div class="email-subject">${subject}</div>
                <div class="email-meta">
                    <span class="email-size">${this.formatBytes(email.size || 0)}</span>
                    <span class="email-time">${timeAgo}</span>
                </div>
            </div>
            <button class="delete-btn" title="Delete email" data-email-id="${email.id}">
                <span>🗑️</span>
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
        const modalContent = document.getElementById('modalContent');
        const toggleText = document.getElementById('toggleText');
        const emailHeaders = document.getElementById('emailHeaders');
        
        if (modalSubject) modalSubject.textContent = emailData.subject;
        if (modalSender) modalSender.textContent = emailData.senderName || emailData.sender;
        if (modalTime) modalTime.textContent = emailData.time;
        if (modalContent) {
            // Display HTML content if available, otherwise plain text
            if (emailData.isHtml) {
                // Sanitize HTML before displaying
                modalContent.innerHTML = this.sanitizeHtml(emailData.content);
            } else {
                // Display plain text (already sanitized)
                modalContent.textContent = emailData.content;
            }
        }
        
        // Reset headers display
        if (toggleText) toggleText.textContent = 'Show Headers';
        if (emailHeaders) {
            emailHeaders.style.display = 'none';
            emailHeaders.innerHTML = '';
        }
        
        if (modalOverlay) {
            modalOverlay.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }
    
    closeModal() {
        const modalOverlay = document.getElementById('modalOverlay');
        if (modalOverlay) {
            modalOverlay.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
        
        // Clear current email data
        this.currentEmailData = null;
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
        const confirmDelete = confirm('Are you sure you want to delete this email?');
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
