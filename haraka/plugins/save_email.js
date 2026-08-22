// SpamEater Email Saving Plugin - Security Enhanced
// Securely processes and stores incoming emails with encryption

const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const DOMPurify = require('isomorphic-dompurify');

// Database connection
const SPAMEATER_HOME = process.env.SPAMEATER_HOME || '/opt/spameater';
const DB_PATH = path.join(SPAMEATER_HOME, 'data', 'emails.db');
const DATA_DIR = path.join(SPAMEATER_HOME, 'data', 'inboxes');

// Encryption settings
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_SALT = 'spameater-v1';

// SECURITY FIX: Require encryption key, no fallback
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
    console.error('[FATAL] ENCRYPTION_KEY not set or too short in environment');
    console.error('Please ensure /opt/spameater/.env contains ENCRYPTION_KEY');
    process.exit(1);
}

let db;
let encryptionKey;

// Initialize database connection and encryption
function initDatabase() {
    db = new sqlite3.Database(DB_PATH, (err) => {
        if (err) {
            console.error('[save_email] Database connection error:', err.message);
        }
    });
    
    // Derive encryption key from environment key
    encryptionKey = crypto.scryptSync(ENCRYPTION_KEY, ENCRYPTION_SALT, 32);
}

// Encrypt data
function encrypt(text) {
    if (!text) return null;
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);
    
    const encrypted = Buffer.concat([
        cipher.update(text, 'utf8'),
        cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Combine IV + authTag + encrypted data
    return Buffer.concat([iv, authTag, encrypted]);
}

// Decrypt data
function decrypt(buffer) {
    if (!buffer || buffer.length < 32) return null;
    
    const iv = buffer.slice(0, 16);
    const authTag = buffer.slice(16, 32);
    const encrypted = buffer.slice(32);
    
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);
    decipher.setAuthTag(authTag);
    
    try {
        const decrypted = Buffer.concat([
            decipher.update(encrypted),
            decipher.final()
        ]);
        return decrypted.toString('utf8');
    } catch (err) {
        console.error('[save_email] Decryption error:', err.message);
        return null;
    }
}

// Generate hash for indexing
function generateHash(text) {
    return crypto.createHash('sha256').update(text || '').digest('hex');
}

// Security: Validate email address format with stricter rules
function isValidEmail(email) {
    // More strict email validation (allows single-char prefixes like "a@domain.com")
    const emailRegex = /^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,48}[a-zA-Z0-9])?@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/;
    
    // Additional validation
    if (!emailRegex.test(email) || email.length > 100) return false;
    
    // Check for consecutive dots
    if (email.includes('..')) return false;
    
    // Normalize and check for Unicode tricks
    const normalized = email.normalize('NFC');
    if (normalized !== email) return false;
    
    return true;
}

// Security: Enhanced text sanitization
function sanitizeText(text, maxLength = 50000) {
    if (!text) return '';
    
    // Remove null bytes and other control characters
    let sanitized = text.replace(/[\0-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');
    
    // Normalize Unicode to prevent homograph attacks
    sanitized = sanitized.normalize('NFC');
    
    // Limit length
    return sanitized.substring(0, maxLength);
}

// SECURITY FIX: HTML sanitization using DOMPurify
// Keeps <style> tags for proper email rendering, removes dangerous elements
// Length cap leaves room for embedded inline images (base64 expands the
// 1MB SMTP message cap by ~1.37x at most)
function sanitizeHtml(html, maxLength = 1500000) {
    if (!html) return '';

    // Remove null bytes and control characters first
    let cleaned = html.replace(/[\0-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');

    // DOMPurify configuration for email safety
    // - ADD_TAGS: ['style'] keeps CSS styling intact for proper email rendering
    // - FORBID_TAGS: blocks dangerous elements that could execute code or phish
    // - FORBID_ATTR: blocks event handlers (DOMPurify blocks these by default too)
    // - ALLOW_DATA_ATTR: false prevents data-* attributes that could be misused
    const sanitized = DOMPurify.sanitize(cleaned, {
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

    // Normalize Unicode to prevent homograph attacks
    const normalized = sanitized.normalize('NFC');

    // Limit length
    return normalized.substring(0, maxLength);
}

// Generate UUID v4
function generateUUID() {
    return crypto.randomUUID();
}

// Extract sender IP from Received headers
function extractSenderIP(receivedHeaders) {
    if (!receivedHeaders || receivedHeaders.length === 0) return null;
    
    // Look for IP in the last (most recent) Received header
    const lastReceived = receivedHeaders[receivedHeaders.length - 1];
    
    // Match IPv4 pattern
    const ipv4Match = lastReceived.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    if (ipv4Match) return ipv4Match[1];
    
    // Match IPv6 pattern
    const ipv6Match = lastReceived.match(/\[([0-9a-fA-F:]+)\]/);
    if (ipv6Match) return ipv6Match[1];
    
    return null;
}

// Log security events
async function logSecurityEvent(eventType, eventData, ipAddress = null, userAgent = null) {
    return new Promise((resolve) => {
        db.run(
            `INSERT INTO security_events (event_type, event_data, ip_address, user_agent)
             VALUES (?, ?, ?, ?)`,
            [eventType, JSON.stringify(eventData), ipAddress, userAgent],
            (err) => {
                if (err) {
                    console.error('[save_email] Failed to log security event:', err.message);
                }
                resolve(); // Don't fail email processing due to logging errors
            }
        );
    });
}

// Save email to database with encryption
async function saveEmail(emailData) {
    return new Promise((resolve, reject) => {
        const emailId = generateUUID();
        
        // Encrypt email bodies
        const encryptedBodyText = encrypt(emailData.bodyText);
        const encryptedBodyHtml = encrypt(emailData.bodyHtml);
        
        // Generate hashes
        const senderHash = generateHash(emailData.sender);
        const bodyTextHash = emailData.bodyText ? generateHash(emailData.bodyText) : null;
        
        db.run(
            `INSERT INTO emails (
                id, inbox_id, sender, sender_name, sender_hash, subject,
                body_text_encrypted, body_html_encrypted, body_text_hash,
                message_id, size_bytes, spf_result, dkim_result, spam_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                emailId,
                emailData.inboxId,
                emailData.sender,
                emailData.senderName,
                senderHash,
                emailData.subject,
                encryptedBodyText,
                encryptedBodyHtml,
                bodyTextHash,
                emailData.messageId,
                emailData.size,
                emailData.spfResult || 'none',
                emailData.dkimResult || 'none',
                emailData.spamScore || 0.0
            ],
            function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve(emailId);
                }
            }
        );
    });
}

// Generate JSON file for frontend polling (with decryption)
async function updateInboxJSON(emailAddress) {
    return new Promise((resolve, reject) => {
        db.all(
            `SELECT e.id, e.sender, e.sender_name, e.subject,
                    e.body_text_encrypted, e.body_html_encrypted,
                    e.received_at, e.size_bytes, e.message_id,
                    e.spf_result, e.dkim_result, i.expires_at
             FROM emails e
             JOIN inboxes i ON e.inbox_id = i.id
             WHERE i.email_address = ?
             ORDER BY e.received_at DESC
             LIMIT 50`,
            [emailAddress],
            async (err, rows) => {
                if (err) {
                    reject(err);
                    return;
                }

                // Decrypt email bodies for JSON output
                const emails = rows.map(row => {
                    const decryptedText = row.body_text_encrypted ? 
                        decrypt(row.body_text_encrypted) : null;
                    const decryptedHtml = row.body_html_encrypted ? 
                        decrypt(row.body_html_encrypted) : null;
                    
                    return {
                        id: row.id,
                        sender: row.sender,
                        senderName: row.sender_name,
                        subject: row.subject,
                        bodyText: decryptedText,
                        bodyHtml: decryptedHtml,
                        receivedAt: row.received_at,
                        size: row.size_bytes,
                        messageId: row.message_id,
                        spfResult: row.spf_result,
                        dkimResult: row.dkim_result
                    };
                });

                const jsonData = {
                    email: emailAddress,
                    count: emails.length,
                    updated: Math.floor(Date.now() / 1000),
                    emails: emails
                };
                if (rows.length > 0 && rows[0].expires_at) {
                    jsonData.expires_at = new Date(rows[0].expires_at * 1000).toISOString();
                }

                try {
                    const prefix = emailAddress.split('@')[0];
                    // Validate prefix to prevent path traversal
                    if (!/^[a-zA-Z0-9._-]+$/.test(prefix) || prefix.includes('..')) {
                        throw new Error('Invalid email prefix');
                    }
                    
                    const jsonPath = path.join(DATA_DIR, `${prefix}.json`);
                    // Double-check path is within DATA_DIR
                    const normalizedPath = path.normalize(jsonPath);
                    if (!normalizedPath.startsWith(DATA_DIR)) {
                        throw new Error('Path traversal attempt');
                    }
                    
                    await fs.writeFile(normalizedPath, JSON.stringify(jsonData, null, 2));
                    resolve();
                } catch (writeErr) {
                    reject(writeErr);
                }
            }
        );
    });
}

// Create empty JSON file for new inbox
async function createEmptyInboxJSON(emailAddress) {
    const prefix = emailAddress.split('@')[0];
    
    // Validate prefix
    if (!/^[a-zA-Z0-9._-]+$/.test(prefix) || prefix.includes('..')) {
        console.error('[save_email] Invalid email prefix:', prefix);
        return;
    }
    
    const jsonPath = path.join(DATA_DIR, `${prefix}.json`);
    
    // Security check
    const normalizedPath = path.normalize(jsonPath);
    if (!normalizedPath.startsWith(DATA_DIR)) {
        console.error('[save_email] Path traversal attempt:', jsonPath);
        return;
    }
    
    const emptyData = {
        email: emailAddress,
        count: 0,
        updated: Math.floor(Date.now() / 1000),
        // New inboxes live 24 hours; the DB default uses the same offset
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        emails: []
    };

    try {
        await fs.writeFile(normalizedPath, JSON.stringify(emptyData, null, 2));
    } catch (err) {
        console.error('[save_email] Failed to create empty JSON:', err.message);
    }
}

// Find or create inbox with race condition protection
async function findOrCreateInbox(emailAddress) {
    return new Promise((resolve, reject) => {
        const prefix = emailAddress.split('@')[0];
        const inboxId = generateUUID();
        
        // Use INSERT OR IGNORE to prevent race conditions
        db.run(
            `INSERT OR IGNORE INTO inboxes (id, email_address, prefix)
             VALUES (?, ?, ?)`,
            [inboxId, emailAddress, prefix],
            function(err) {
                if (err) {
                    reject(err);
                    return;
                }
                
                // Get the inbox ID (either newly created or existing)
                db.get(
                    'SELECT id FROM inboxes WHERE email_address = ?',
                    [emailAddress],
                    async (selectErr, row) => {
                        if (selectErr) {
                            reject(selectErr);
                        } else if (row) {
                            // If this was a new insert, create empty JSON
                            if (this.changes > 0) {
                                await createEmptyInboxJSON(emailAddress);
                            }
                            resolve(row.id);
                        } else {
                            reject(new Error('Failed to create or find inbox'));
                        }
                    }
                );
            }
        );
    });
}

// Read allowed domains from host_list file
async function getAllowedDomains() {
    try {
        const hostListPath = path.join(SPAMEATER_HOME, 'haraka', 'config', 'host_list');
        const content = await fs.readFile(hostListPath, 'utf8');
        return content.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
    } catch (err) {
        console.error('[save_email] Error reading host_list:', err.message);
        return [];
    }
}

// Plugin exports
exports.register = function() {
    initDatabase();
    this.loginfo('SpamEater save_email plugin loaded (with encryption)');
};

// Hook: Validate recipient
exports.hook_rcpt = async function(next, connection, params) {
    const plugin = this;
    const recipient = params[0].address();
    const senderIp = connection.remote.ip;
    
    // Security: Validate email format
    if (!isValidEmail(recipient)) {
        await logSecurityEvent('invalid_input', { 
            recipient, 
            reason: 'invalid_email_format' 
        }, senderIp);
        return next(DENY, 'Invalid email address format');
    }
    
    // Get recipient domain
    const recipientDomain = recipient.split('@')[1];
    
    // Check against allowed domains from host_list
    const allowedDomains = await getAllowedDomains();
    
    if (!allowedDomains.includes(recipientDomain)) {
        await logSecurityEvent('invalid_input', { 
            recipient, 
            reason: 'domain_not_allowed',
            domain: recipientDomain 
        }, senderIp);
        return next(DENY, `Mail for domain ${recipientDomain} not accepted here`);
    }
    
    return next(OK);
};

// Hook: Queue handler to acknowledge email (prevents 451 error)
exports.hook_queue = function(next, connection) {
    return next(OK);
};

// Inline image capture limits. Raster formats only (no SVG: it can carry
// script and there is no reason a signature logo needs it).
const INLINE_IMAGE_TYPES = /^image\/(png|jpe?g|gif|webp|bmp)\s*(;|$)/i;
const MAX_INLINE_IMAGE_BYTES = 200 * 1024;
const MAX_INLINE_TOTAL_BYTES = 400 * 1024;

// Replace cid: references with data: URIs for captured inline images.
// Unmatched references are left alone; the frontend shows a placeholder.
function embedInlineImages(html, inlineImages) {
    if (!html || !inlineImages || Object.keys(inlineImages).length === 0) return html;
    return html.replace(/(["'(])cid:([^"'()\s>]+)/gi, (match, lead, cid) => {
        const key = Object.keys(inlineImages).find(k => k.toLowerCase() === cid.toLowerCase());
        if (!key) return match;
        const image = inlineImages[key];
        return `${lead}data:${image.contentType};base64,${image.base64}`;
    });
}
exports._embedInlineImages = embedInlineImages;

// Hook: Process data (this is where we can access the email body)
exports.hook_data = function(next, connection) {
    const transaction = connection.transaction;
    transaction.parse_body = true;
    transaction.notes.inline_images = {};
    transaction.notes.inline_images_bytes = 0;

    // Attachments stream through Haraka without being kept; buffer just the
    // small inline raster images that the HTML can reference by Content-ID.
    transaction.attachment_hooks((contentType, filename, body, stream) => {
        const cid = body && body.header ? String(body.header.get('content-id') || '').trim() : '';
        if (!INLINE_IMAGE_TYPES.test(contentType || '') || !cid) {
            stream.resume();
            return;
        }
        const chunks = [];
        let size = 0;
        stream.on('data', (chunk) => {
            size += chunk.length;
            if (size <= MAX_INLINE_IMAGE_BYTES) chunks.push(chunk);
        });
        stream.on('end', () => {
            if (size === 0 || size > MAX_INLINE_IMAGE_BYTES) return;
            if (transaction.notes.inline_images_bytes + size > MAX_INLINE_TOTAL_BYTES) return;
            const key = cid.replace(/^</, '').replace(/>$/, '');
            transaction.notes.inline_images[key] = {
                contentType: (contentType.split(';')[0] || '').trim().toLowerCase(),
                base64: Buffer.concat(chunks).toString('base64')
            };
            transaction.notes.inline_images_bytes += size;
        });
        stream.on('error', () => {});
    });

    return next();
};

// Hook: Process and save email after data is complete
exports.hook_data_post = function(next, connection) {
    const plugin = this;
    const transaction = connection.transaction;
    const senderIp = connection.remote.ip;
    
    try {
        // Extract email data
        const recipients = transaction.rcpt_to.map(rcpt => rcpt.address());
        const sender = transaction.mail_from ? transaction.mail_from.address() : 'unknown@unknown.com';
        const messageId = (transaction.header.get('Message-ID') || generateUUID()).trim();
        // Haraka header.get() keeps the trailing newline; trim it
        const subject = sanitizeText((transaction.header.get('Subject') || '(No subject)').trim(), 1000);
        
        // Get sender name from From header
        const fromHeader = (transaction.header.get('From') || sender).trim();
        let senderName = fromHeader;
        const nameMatch = fromHeader.match(/^"?([^"<]+)"?\s*</);
        if (nameMatch) {
            senderName = nameMatch[1].trim();
        }
        
        // Get authentication results
        let spfResult = 'none';
        let dkimResult = 'none';
        
        // Check SPF result
        if (connection.transaction.results && connection.transaction.results.get('spf')) {
            const spfData = connection.transaction.results.get('spf');
            if (spfData && spfData.result) {
                spfResult = spfData.result.toLowerCase();
            }
        }
        
        // Check DKIM result
        if (connection.transaction.results && connection.transaction.results.get('dkim')) {
            const dkimData = connection.transaction.results.get('dkim');
            if (dkimData && dkimData.pass && dkimData.pass.length > 0) {
                dkimResult = 'pass';
            } else if (dkimData && dkimData.fail && dkimData.fail.length > 0) {
                dkimResult = 'fail';
            }
        }
        
        // Parse email body. Forwarded and attachment-bearing mail nests the
        // text parts (multipart/mixed > multipart/alternative > text/*), so
        // the whole part tree is walked, first match per type wins.
        let bodyText = '';
        let bodyHtml = '';

        const collectBodies = (part) => {
            if (!part) return;
            const ct = (part.header && part.header.get('content-type')) || '';
            if (part.bodytext && part.bodytext.trim()) {
                if (/text\/html/i.test(ct)) {
                    if (!bodyHtml.trim()) bodyHtml = part.bodytext;
                } else if (/text\/plain/i.test(ct)) {
                    if (!bodyText.trim()) bodyText = part.bodytext;
                } else if (!/multipart\/|message\/|image\/|audio\/|video\/|application\//i.test(ct)) {
                    // No or unrecognized content type: classify by content
                    if (/<html|<!DOCTYPE/i.test(part.bodytext)) {
                        if (!bodyHtml.trim()) bodyHtml = part.bodytext;
                    } else if (!bodyText.trim()) {
                        bodyText = part.bodytext;
                    }
                }
            }
            if (part.children && part.children.length > 0) {
                for (const child of part.children) collectBodies(child);
            }
        };
        collectBodies(transaction.body);
        
        // Fallback to body_lines if nothing found
        if (!bodyText && !bodyHtml) {
            const body_lines = transaction.body_lines;
            if (body_lines && body_lines.length > 0) {
                const joinedBody = body_lines.join('\n');
                // Check if it's HTML
                if (/<html|<!DOCTYPE/i.test(joinedBody)) {
                    bodyHtml = joinedBody;
                } else {
                    bodyText = joinedBody;
                }
            }
        }
        
        // Sanitize bodies
        bodyText = sanitizeText(bodyText);
        // Embed captured inline images before sanitizing (sanitizer keeps
        // data: URIs on images)
        bodyHtml = embedInlineImages(bodyHtml, transaction.notes.inline_images);
        bodyHtml = sanitizeHtml(bodyHtml);
        
        // Calculate size
        const size = Buffer.byteLength(bodyText + bodyHtml, 'utf8');
        
        // Security: Size check
        if (size > 10485760) { // 10MB limit
            logSecurityEvent('invalid_input', { 
                sender, 
                size,
                reason: 'message_too_large' 
            }, senderIp).catch(() => {});
            return next(DENY, 'Message too large');
        }
        
        // Check for suspicious patterns
        const suspiciousPatterns = [
            /\bviagra\b/i,
            /\bcialis\b/i,
            /\bcasino\b/i,
            /\bclick here now\b/i,
            /\blimited time offer\b/i
        ];
        
        const combinedText = subject + ' ' + bodyText + ' ' + bodyHtml;
        let spamScore = 0;
        
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(combinedText)) {
                spamScore += 1;
            }
        }
        
        if (spamScore > 2) {
            logSecurityEvent('suspicious_pattern', { 
                sender, 
                subject,
                spamScore,
                patterns: 'spam_keywords' 
            }, senderIp).catch(() => {});
        }
        
        // Process each recipient
        const savePromises = recipients.map(async (recipient) => {
            try {
                const inboxId = await findOrCreateInbox(recipient);
                
                const emailData = {
                    inboxId,
                    sender: sanitizeText(sender, 255),
                    senderName: sanitizeText(senderName, 255),
                    subject,
                    bodyText,
                    bodyHtml,
                    messageId: sanitizeText(messageId, 255),
                    size,
                    spfResult,
                    dkimResult,
                    spamScore
                };
                
                // Save to database
                await saveEmail(emailData);
                
                // Update JSON file
                await updateInboxJSON(recipient);
                
            } catch (err) {
                plugin.logerror(`[save_email] Error processing ${recipient}: ${err.message}`);
                throw err;
            }
        });
        
        // Wait for all saves to complete
        Promise.all(savePromises)
            .then(() => next(OK))
            .catch((err) => {
                logSecurityEvent('auth_failure', { 
                    error: err.message,
                    sender 
                }, senderIp).catch(() => {});
                plugin.logerror('[save_email] Processing error: ' + err.message);
                next(DENYSOFT, 'Temporary processing error');
            });
            
    } catch (err) {
        plugin.logerror('[save_email] Parsing error: ' + err.message);
        return next(DENYSOFT, 'Message processing failed');
    }
};
