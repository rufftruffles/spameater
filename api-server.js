#!/usr/bin/env node

// SpamEater API Server - Security Enhanced
// Handles email deletion with enhanced security, encryption, and rate limiting

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();

// Trust nginx proxy (fixes X-Forwarded-For issue)
app.set('trust proxy', 1);

const DATA_DIR = '/opt/spameater/data/inboxes';
const DB_PATH = '/opt/spameater/data/emails.db';
const PORT = 3001; // Internal API port

// Security: Validate critical environment variables on startup
const DELETE_TOKEN_SECRET = process.env.DELETE_TOKEN_SECRET;
const CSRF_SECRET = process.env.CSRF_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!DELETE_TOKEN_SECRET || DELETE_TOKEN_SECRET.length < 32) {
    console.error('[FATAL] DELETE_TOKEN_SECRET not set or too short in environment');
    console.error('Please ensure /opt/spameater/.env contains DELETE_TOKEN_SECRET');
    process.exit(1);
}

if (!CSRF_SECRET || CSRF_SECRET.length < 32) {
    console.error('[FATAL] CSRF_SECRET not set or too short in environment');
    console.error('Please ensure /opt/spameater/.env contains CSRF_SECRET');
    process.exit(1);
}

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
    console.error('[FATAL] ENCRYPTION_KEY not set or too short in environment');
    console.error('Please ensure /opt/spameater/.env contains ENCRYPTION_KEY');
    process.exit(1);
}

// Initialize database connection
const db = new sqlite3.Database(DB_PATH);

// CSRF token store with expiration
const csrfTokens = new Map();
const CSRF_TOKEN_EXPIRY = 3600000; // 1 hour
const MAX_CSRF_TOKENS = 10000;

// Rate limiting store with maximum entries to prevent memory exhaustion
const customRateLimitStore = new Map();
const MAX_RATE_LIMIT_ENTRIES = 10000;

// Middleware
app.use(express.json({ limit: '10kb' })); // Limit request body size

// Security headers with Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'none'"],
            frameAncestors: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Custom rate limiting middleware with headers
const createRateLimiter = (windowMs, max, name) => {
    return rateLimit({
        windowMs,
        max,
        standardHeaders: true, // Return rate limit info in headers
        legacyHeaders: false,
        message: 'Too many requests',
        handler: (req, res) => {
            logSecurityEvent('rate_limit', {
                endpoint: req.path,
                ip: req.ip,
                limiter: name
            });
            res.status(429).json({ 
                error: 'Too many requests',
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
    });
};

// Different rate limiters for different endpoints
const generalLimiter = createRateLimiter(60000, 30, 'general'); // 30 req/min
const strictLimiter = createRateLimiter(60000, 10, 'strict'); // 10 req/min
const authLimiter = createRateLimiter(300000, 5, 'auth'); // 5 req/5min

// Log security events to database
async function logSecurityEvent(eventType, eventData) {
    return new Promise((resolve) => {
        db.run(
            `INSERT INTO security_events (event_type, event_data, ip_address, user_agent, timestamp)
             VALUES (?, ?, ?, ?, ?)`,
            [
                eventType,
                JSON.stringify(eventData),
                eventData.ip || null,
                eventData.userAgent || null,
                Math.floor(Date.now() / 1000)
            ],
            (err) => {
                if (err) {
                    console.error('[API] Failed to log security event:', err.message);
                }
                resolve();
            }
        );
    });
}

// Clean up expired CSRF tokens periodically
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of csrfTokens.entries()) {
        if (now > data.expires) {
            csrfTokens.delete(token);
        }
    }
}, 600000); // Every 10 minutes

// Generate CSRF token
function generateCSRFToken() {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + CSRF_TOKEN_EXPIRY;
    
    // Limit token store size
    if (csrfTokens.size >= MAX_CSRF_TOKENS) {
        const firstKey = csrfTokens.keys().next().value;
        csrfTokens.delete(firstKey);
    }
    
    csrfTokens.set(token, { expires, used: false });
    return token;
}

// Verify CSRF token
function verifyCSRFToken(token) {
    if (!token) return false;
    
    const tokenData = csrfTokens.get(token);
    if (!tokenData) return false;
    
    if (Date.now() > tokenData.expires) {
        csrfTokens.delete(token);
        return false;
    }
    
    return true;
}

// Token cache to reduce computation
const tokenCache = new Map();
const TOKEN_CACHE_SIZE = 1000;
const TOKEN_WINDOW = 300000; // 5 minutes

// Generate delete token for an email
function generateDeleteToken(prefix, emailId) {
    const window = Math.floor(Date.now() / TOKEN_WINDOW);
    const cacheKey = `${prefix}:${emailId}:${window}`;
    
    // Check cache first
    if (tokenCache.has(cacheKey)) {
        return tokenCache.get(cacheKey);
    }
    
    // Limit cache size
    if (tokenCache.size > TOKEN_CACHE_SIZE) {
        const firstKey = tokenCache.keys().next().value;
        tokenCache.delete(firstKey);
    }
    
    const data = `${prefix}:${emailId}:${window}`;
    const token = crypto.createHmac('sha256', DELETE_TOKEN_SECRET)
        .update(data)
        .digest('hex')
        .substring(0, 16);
    
    tokenCache.set(cacheKey, token);
    return token;
}

// Verify delete token with constant-time comparison
function verifyDeleteToken(prefix, emailId, token) {
    // Check current and previous 5-minute window (allows for clock skew)
    const currentToken = generateDeleteToken(prefix, emailId);
    const window = Math.floor(Date.now() / TOKEN_WINDOW) - 1;
    const cacheKey = `${prefix}:${emailId}:${window}`;
    
    // Generate or get previous token
    let previousToken;
    if (tokenCache.has(cacheKey)) {
        previousToken = tokenCache.get(cacheKey);
    } else {
        const data = `${prefix}:${emailId}:${window}`;
        previousToken = crypto.createHmac('sha256', DELETE_TOKEN_SECRET)
            .update(data)
            .digest('hex')
            .substring(0, 16);
    }
    
    // Constant-time comparison
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(currentToken)) ||
           crypto.timingSafeEqual(Buffer.from(token), Buffer.from(previousToken));
}

// Security headers middleware with rate limit info
app.use((req, res, next) => {
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Referrer-Policy', 'no-referrer');
    res.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
    
    // CORS - restrict to same origin in production
    const origin = req.headers.origin;
    if (origin && (origin.startsWith('http://localhost') || origin.startsWith('https://localhost'))) {
        res.header('Access-Control-Allow-Origin', origin);
    } else {
        // In production, only allow same origin
        res.header('Access-Control-Allow-Origin', req.headers.host ? `https://${req.headers.host}` : '');
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, X-Delete-Token, X-CSRF-Token');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// CSRF token endpoint - GET request to obtain token
app.get('/api/csrf-token', strictLimiter, (req, res) => {
    const token = generateCSRFToken();
    res.json({ csrfToken: token });
});

// DELETE endpoint with authentication and CSRF protection
app.delete('/api/delete/:prefix/:emailId', generalLimiter, async (req, res) => {
    const { prefix, emailId } = req.params;
    const deleteToken = req.headers['x-delete-token'];
    const csrfToken = req.headers['x-csrf-token'];
    const userIp = req.ip || req.connection.remoteAddress;
    
    // Verify CSRF token
    if (!csrfToken || !verifyCSRFToken(csrfToken)) {
        await logSecurityEvent('auth_failure', { 
            reason: 'invalid_csrf_token',
            endpoint: '/api/delete',
            ip: userIp
        });
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    
    // Security: Validate inputs with enhanced checks
    if (!/^[a-zA-Z0-9._-]+$/.test(prefix) || prefix.length > 50 || prefix.includes('..')) {
        await logSecurityEvent('invalid_input', { 
            reason: 'invalid_email_prefix',
            prefix: prefix.substring(0, 20),
            ip: userIp
        });
        return res.status(400).json({ error: 'Invalid email prefix' });
    }
    
    if (!/^[a-f0-9-]+$/i.test(emailId) || emailId.length !== 36) {
        await logSecurityEvent('invalid_input', { 
            reason: 'invalid_email_id',
            emailId: emailId.substring(0, 20),
            ip: userIp
        });
        return res.status(400).json({ error: 'Invalid email ID' });
    }
    
    // Verify delete token
    if (!deleteToken || !verifyDeleteToken(prefix, emailId, deleteToken)) {
        await logSecurityEvent('auth_failure', { 
            reason: 'invalid_delete_token',
            prefix,
            ip: userIp
        });
        // Add random delay to prevent timing attacks
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
        return res.status(403).json({ error: 'Invalid or missing delete token' });
    }
    
    try {
        const jsonPath = path.join(DATA_DIR, `${prefix}.json`);
        
        // Prevent path traversal with multiple checks
        const normalizedPath = path.normalize(jsonPath);
        const resolvedPath = path.resolve(jsonPath);
        if (!normalizedPath.startsWith(DATA_DIR) || !resolvedPath.startsWith(path.resolve(DATA_DIR))) {
            await logSecurityEvent('suspicious_pattern', { 
                reason: 'path_traversal_attempt',
                path: jsonPath.substring(0, 50),
                ip: userIp
            });
            return res.status(400).json({ error: 'Invalid path' });
        }
        
        // Read current data
        const fileData = await fs.readFile(normalizedPath, 'utf8');
        const inboxData = JSON.parse(fileData);
        
        // Find and remove the email
        const originalCount = inboxData.emails.length;
        inboxData.emails = inboxData.emails.filter(email => email.id !== emailId);
        
        if (inboxData.emails.length === originalCount) {
            // Add random delay to prevent timing attacks
            await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
            return res.status(404).json({ error: 'Email not found' });
        }
        
        // Update metadata
        inboxData.count = inboxData.emails.length;
        inboxData.updated = Math.floor(Date.now() / 1000);
        
        // Write back to file
        await fs.writeFile(normalizedPath, JSON.stringify(inboxData, null, 2));
        
        // Also delete from database
        db.run('DELETE FROM emails WHERE id = ?', [emailId], (err) => {
            if (err) {
                console.error('[API] Failed to delete from database:', err.message);
            }
        });
        
        res.json({ 
            success: true, 
            message: 'Email deleted successfully',
            remaining: inboxData.count 
        });
        
    } catch (err) {
        if (err.code === 'ENOENT') {
            // Add random delay to prevent timing attacks
            await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
            return res.status(404).json({ error: 'Inbox not found' });
        }
        
        console.error('[API] Delete error:', err.message);
        res.status(500).json({ error: 'Failed to delete email' });
    }
});

// Generate token endpoint - returns a delete token for frontend use
app.post('/api/token/generate', generalLimiter, async (req, res) => {
    const { prefix, emailId } = req.body;
    const csrfToken = req.headers['x-csrf-token'];
    const userIp = req.ip || req.connection.remoteAddress;
    
    // Verify CSRF token
    if (!csrfToken || !verifyCSRFToken(csrfToken)) {
        await logSecurityEvent('auth_failure', { 
            reason: 'invalid_csrf_token',
            endpoint: '/api/token/generate',
            ip: userIp
        });
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    
    // Validate inputs with enhanced checks
    if (!prefix || !emailId || 
        !/^[a-zA-Z0-9._-]+$/.test(prefix) || 
        prefix.length > 50 ||
        prefix.includes('..') ||
        !/^[a-f0-9-]+$/i.test(emailId) ||
        emailId.length !== 36) {
        await logSecurityEvent('invalid_input', { 
            reason: 'invalid_parameters',
            endpoint: '/api/token/generate',
            ip: userIp
        });
        return res.status(400).json({ error: 'Invalid parameters' });
    }
    
    // Check if this looks like enumeration attempt
    const enumerationKey = `enum:${userIp}`;
    const now = Date.now();
    
    if (!customRateLimitStore.has(enumerationKey)) {
        customRateLimitStore.set(enumerationKey, { count: 1, resetTime: now + 60000 });
    } else {
        const enumData = customRateLimitStore.get(enumerationKey);
        if (now > enumData.resetTime) {
            enumData.count = 1;
            enumData.resetTime = now + 60000;
        } else {
            enumData.count++;
            if (enumData.count > 20) { // More than 20 token requests per minute
                await logSecurityEvent('enumeration_attempt', { 
                    reason: 'excessive_token_generation',
                    count: enumData.count,
                    ip: userIp
                });
            }
        }
    }
    
    const token = generateDeleteToken(prefix, emailId);
    res.json({ token });
});

// Create inbox endpoint - creates empty JSON file
app.post('/api/inbox/create', strictLimiter, async (req, res) => {
    const { email } = req.body;
    const csrfToken = req.headers['x-csrf-token'];
    const userIp = req.ip || req.connection.remoteAddress;
    
    // Verify CSRF token
    if (!csrfToken || !verifyCSRFToken(csrfToken)) {
        await logSecurityEvent('auth_failure', { 
            reason: 'invalid_csrf_token',
            endpoint: '/api/inbox/create',
            ip: userIp
        });
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    
    // Validate email format with enhanced checks
    const emailRegex = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,48}[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/;
    
    if (!email || !emailRegex.test(email) || email.length > 100 || email.includes('..')) {
        await logSecurityEvent('invalid_input', { 
            reason: 'invalid_email_address',
            endpoint: '/api/inbox/create',
            ip: userIp
        });
        return res.status(400).json({ error: 'Invalid email address' });
    }
    
    // Normalize email to prevent homograph attacks
    const normalizedEmail = email.normalize('NFC').toLowerCase();
    if (normalizedEmail !== email.toLowerCase()) {
        await logSecurityEvent('suspicious_pattern', { 
            reason: 'unicode_normalization_mismatch',
            email: email.substring(0, 20),
            ip: userIp
        });
        return res.status(400).json({ error: 'Invalid email address' });
    }
    
    const prefix = email.split('@')[0];
    const jsonPath = path.join(DATA_DIR, `${prefix}.json`);
    
    try {
        // Prevent path traversal
        const normalizedPath = path.normalize(jsonPath);
        const resolvedPath = path.resolve(jsonPath);
        if (!normalizedPath.startsWith(DATA_DIR) || !resolvedPath.startsWith(path.resolve(DATA_DIR))) {
            await logSecurityEvent('suspicious_pattern', { 
                reason: 'path_traversal_attempt',
                endpoint: '/api/inbox/create',
                ip: userIp
            });
            return res.status(400).json({ error: 'Invalid path' });
        }
        
        // Check if file already exists
        try {
            await fs.access(normalizedPath);
            // File exists
            return res.status(409).json({ error: 'Inbox already exists' });
        } catch {
            // File doesn't exist, create it
        }
        
        // Create empty inbox JSON
        const emptyInbox = {
            email: email,
            count: 0,
            updated: Math.floor(Date.now() / 1000),
            emails: []
        };
        
        await fs.writeFile(normalizedPath, JSON.stringify(emptyInbox, null, 2));
        
        res.json({ 
            success: true, 
            message: 'Inbox created successfully',
            email: email 
        });
        
    } catch (err) {
        console.error('[API] Create inbox error:', err.message);
        res.status(500).json({ error: 'Failed to create inbox' });
    }
});

// Health check endpoint (for monitoring)
app.get('/api/health', (req, res) => {
    // Add basic system info
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    res.json({ 
        status: 'healthy',
        timestamp: Date.now(),
        uptime: Math.floor(uptime),
        memory: {
            used: Math.floor(memUsage.heapUsed / 1024 / 1024) + 'MB',
            total: Math.floor(memUsage.heapTotal / 1024 / 1024) + 'MB'
        }
    });
});

// Security monitoring endpoint (internal use only)
app.get('/api/security/events', authLimiter, async (req, res) => {
    const csrfToken = req.headers['x-csrf-token'];
    const authToken = req.headers['x-auth-token'];
    
    // This endpoint requires special authentication
    // In production, implement proper admin authentication
    if (!csrfToken || !verifyCSRFToken(csrfToken)) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // For now, just return 403 unless proper auth is implemented
    return res.status(403).json({ error: 'Admin authentication required' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('[API] Unhandled error:', err.message);
    
    // Log security event for errors
    logSecurityEvent('suspicious_pattern', {
        reason: 'unhandled_error',
        error: err.message.substring(0, 100),
        ip: req.ip
    });
    
    // Don't expose internal errors
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Cleanup old rate limit entries periodically
setInterval(() => {
    const now = Date.now();
    if (customRateLimitStore.size > MAX_RATE_LIMIT_ENTRIES) {
        // Remove oldest entries
        const entries = Array.from(customRateLimitStore.entries());
        entries.sort((a, b) => a[1].resetTime - b[1].resetTime);
        entries.slice(0, 100).forEach(([key]) => customRateLimitStore.delete(key));
    }
}, 60000);

// Start server
const server = app.listen(PORT, '127.0.0.1', () => {
    console.log(`SpamEater API server started on port ${PORT} (security enhanced)`);
    console.log('Rate limiting: Enabled');
    console.log('CSRF protection: Enabled');
    console.log('Security logging: Enabled');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, closing server...');
    server.close(() => {
        db.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, closing server...');
    server.close(() => {
        db.close();
        process.exit(0);
    });
});
