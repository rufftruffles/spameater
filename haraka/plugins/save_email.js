// SpamEater Email Saving Plugin - Security Enhanced
// Securely processes and stores incoming emails with encryption

const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

// Database connection
const DB_PATH = '/opt/spameater/data/emails.db';
const DATA_DIR = '/opt/spameater/data/inboxes';

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

// SECURITY FIX: Enhanced HTML sanitization
function sanitizeHtml(html, maxLength = 500000) {
    if (!html) return '';
    
    // Remove null bytes and control characters
    let sanitized = html.replace(/[\0-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');
    
    // Remove all script tags and their content
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    
    // Remove all style tags and their content
    sanitized = sanitized.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
    
    // Remove all event handlers (more comprehensive)
    sanitized = sanitized.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
    sanitized = sanitized.replace(/\s*on\w+\s*=\s*[^\s>]*/gi, '');
    
    // Remove javascript: and vbscript: protocols
    sanitized = sanitized.replace(/javascript:/gi, '');
    sanitized = sanitized.replace(/vbscript:/gi, '');
    
    // Remove data: URLs in src/href attributes (except images)
    sanitized = sanitized.replace(/(<[^>]+)\s(src|href)\s*=\s*["']?\s*data:(?!image\/)[^"'\s>]*/gi, '$1');
    
    // Remove dangerous tags
    const dangerousTags = [
        'script', 'style', 'iframe', 'frame', 'frameset', 'object', 
        'embed', 'applet', 'link', 'meta', 'base', 'form'
    ];
    
    dangerousTags.forEach(tag => {
        const regex = new RegExp(`<${tag}\\b[^<]*(?:(?!<\\/${tag}>)<[^<]*)*<\\/${tag}>|<${tag}\\b[^>]*\\/?>`, 'gi');
        sanitized = sanitized.replace(regex, '');
    });
    
    // Remove dangerous attributes
    const dangerousAttrs = [
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
        'onchange', 'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress',
        'onmouseout', 'onmouseenter', 'onmouseleave', 'onmousemove',
        'ondblclick', 'oncontextmenu', 'onwheel', 'ondrag', 'ondrop',
        'oncopy', 'oncut', 'onpaste'
    ];
    
    dangerousAttrs.forEach(attr => {
        const regex = new RegExp(`\\s*${attr}\\s*=\\s*["'][^"']*["']`, 'gi');
        sanitized = sanitized.replace(regex, '');
    });
    
    // Clean up any broken tags
    sanitized = sanitized.replace(/<[^>]*$/g, '');
    
    // Normalize Unicode to prevent homograph attacks
    sanitized = sanitized.normalize('NFC');
    
    // Limit length
    return sanitized.substring(0, maxLength);
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
                    e.spf_result, e.dkim_result
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
        const hostListPath = '/opt/spameater/haraka/config/host_list';
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

// Hook: Process data (this is where we can access the email body)
exports.hook_data = function(next, connection) {
    connection.transaction.parse_body = true;
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
        const messageId = transaction.header.get('Message-ID') || generateUUID();
        const subject = sanitizeText(transaction.header.get('Subject') || '(No subject)', 1000);
        
        // Get sender name from From header
        const fromHeader = transaction.header.get('From') || sender;
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
        
        // Parse email body - FIXED LOGIC
        let bodyText = '';
        let bodyHtml = '';
        
        if (transaction.body) {
            // First check if the main body has content
            if (transaction.body.bodytext) {
                const mainBodyText = transaction.body.bodytext;
                // Check if it's HTML by looking for HTML tags
                if (/<html|<!DOCTYPE/i.test(mainBodyText)) {
                    bodyHtml = mainBodyText;
                } else {
                    bodyText = mainBodyText;
                }
            }
            
            // Then check children for multipart messages
            if (transaction.body.children && transaction.body.children.length > 0) {
                for (let i = 0; i < transaction.body.children.length; i++) {
                    const child = transaction.body.children[i];
                    if (child.bodytext) {
                        const ct = child.header.get('content-type') || '';
                        if (/text\/plain/i.test(ct)) {
                            // Only set plain text if we don't already have it
                            if (!bodyText || bodyText.trim() === '') {
                                bodyText = child.bodytext;
                            }
                        } else if (/text\/html/i.test(ct)) {
                            // Only set HTML if we don't already have it
                            if (!bodyHtml || bodyHtml.trim() === '') {
                                bodyHtml = child.bodytext;
                            }
                        }
                    }
                }
            }
        }
        
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
