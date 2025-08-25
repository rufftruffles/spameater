// SpamEater SMTP Rate Limiting Plugin - Security Enhanced
// Prevents email bombing by limiting emails per inbox with IPv6 support

const crypto = require('crypto');

const RATE_LIMITS = {
    per_minute: 10,      // Max emails per minute per inbox
    per_hour: 100,       // Max emails per hour per inbox
    per_day: 500,        // Max emails per day per inbox
    burst: 5,            // Allow burst of 5 emails
    
    // IP-based limits
    ip_per_minute: 30,   // Max emails per minute per IP
    ip_per_hour: 300,    // Max emails per hour per IP
};

// In-memory store for rate limiting
const rateStore = new Map();
const ipRateStore = new Map();

// Clean up old entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    
    // Clean inbox rate limits
    for (const [key, data] of rateStore.entries()) {
        if (now - data.lastReset > 86400000) { // 24 hours
            rateStore.delete(key);
        }
    }
    
    // Clean IP rate limits
    for (const [key, data] of ipRateStore.entries()) {
        if (now - data.lastReset > 3600000) { // 1 hour
            ipRateStore.delete(key);
        }
    }
}, 300000);

// Normalize IPv6 addresses to /64 subnet
function normalizeIPv6(ip) {
    // Check if it's IPv6
    if (!ip.includes(':')) return ip;
    
    // Expand shortened IPv6
    const parts = ip.split(':');
    if (parts.length < 8) {
        // Handle :: notation
        const emptyIndex = parts.indexOf('');
        if (emptyIndex >= 0) {
            const before = parts.slice(0, emptyIndex);
            const after = parts.slice(emptyIndex + 1);
            const missing = 8 - before.length - after.length;
            const expanded = [...before, ...Array(missing).fill('0000'), ...after];
            ip = expanded.join(':');
        }
    }
    
    // Get /64 subnet (first 4 groups)
    return ip.split(':').slice(0, 4).join(':') + '::';
}

// Generate hash for IP (for privacy in logs)
function hashIP(ip) {
    return crypto.createHash('sha256').update(ip).digest('hex').substring(0, 16);
}

exports.register = function() {
    this.loginfo('SpamEater rate limiting plugin loaded (with IPv6 support)');
};

exports.hook_rcpt = function(next, connection, params) {
    const plugin = this;
    const recipient = params[0].address().toLowerCase();
    const rawIP = connection.remote.ip;
    const normalizedIP = normalizeIPv6(rawIP);
    const now = Date.now();
    
    // Check IP-based rate limits first
    let ipData = ipRateStore.get(normalizedIP);
    
    if (!ipData) {
        ipData = {
            minuteCount: 0,
            hourCount: 0,
            lastMinute: now,
            lastHour: now,
            lastReset: now
        };
        ipRateStore.set(normalizedIP, ipData);
    }
    
    // Reset IP counters if time windows have passed
    if (now - ipData.lastMinute > 60000) {
        ipData.minuteCount = 0;
        ipData.lastMinute = now;
    }
    
    if (now - ipData.lastHour > 3600000) {
        ipData.hourCount = 0;
        ipData.lastHour = now;
    }
    
    // Check IP rate limits
    if (ipData.minuteCount >= RATE_LIMITS.ip_per_minute) {
        plugin.logwarn(`IP rate limit exceeded for ${hashIP(normalizedIP)} - minute limit`);
        // Log to notes for save_email plugin
        connection.transaction.notes.rate_limit_exceeded = true;
        connection.transaction.notes.rate_limit_type = 'ip_minute';
        return next(DENYSOFT, 'Rate limit exceeded. Please try again later.');
    }
    
    if (ipData.hourCount >= RATE_LIMITS.ip_per_hour) {
        plugin.logwarn(`IP rate limit exceeded for ${hashIP(normalizedIP)} - hour limit`);
        connection.transaction.notes.rate_limit_exceeded = true;
        connection.transaction.notes.rate_limit_type = 'ip_hour';
        return next(DENYSOFT, 'Hourly rate limit exceeded. Please try again later.');
    }
    
    // Get or create rate limit data for this inbox
    let inboxData = rateStore.get(recipient);
    
    if (!inboxData) {
        inboxData = {
            minuteCount: 0,
            hourCount: 0,
            dayCount: 0,
            lastMinute: now,
            lastHour: now,
            lastDay: now,
            lastReset: now,
            tokens: RATE_LIMITS.burst // Token bucket for burst handling
        };
        rateStore.set(recipient, inboxData);
    }
    
    // Reset counters if time windows have passed
    if (now - inboxData.lastMinute > 60000) {
        inboxData.minuteCount = 0;
        inboxData.lastMinute = now;
        // Refill burst tokens
        inboxData.tokens = Math.min(RATE_LIMITS.burst, inboxData.tokens + 1);
    }
    
    if (now - inboxData.lastHour > 3600000) {
        inboxData.hourCount = 0;
        inboxData.lastHour = now;
    }
    
    if (now - inboxData.lastDay > 86400000) {
        inboxData.dayCount = 0;
        inboxData.lastDay = now;
    }
    
    // Check rate limits
    if (inboxData.minuteCount >= RATE_LIMITS.per_minute && inboxData.tokens <= 0) {
        plugin.logwarn(`Rate limit exceeded for ${recipient} - minute limit`);
        connection.transaction.notes.rate_limit_exceeded = true;
        connection.transaction.notes.rate_limit_type = 'inbox_minute';
        return next(DENYSOFT, 'Rate limit exceeded. Please try again later.');
    }
    
    if (inboxData.hourCount >= RATE_LIMITS.per_hour) {
        plugin.logwarn(`Rate limit exceeded for ${recipient} - hour limit`);
        connection.transaction.notes.rate_limit_exceeded = true;
        connection.transaction.notes.rate_limit_type = 'inbox_hour';
        return next(DENYSOFT, 'Hourly rate limit exceeded. Please try again later.');
    }
    
    if (inboxData.dayCount >= RATE_LIMITS.per_day) {
        plugin.logwarn(`Rate limit exceeded for ${recipient} - day limit`);
        connection.transaction.notes.rate_limit_exceeded = true;
        connection.transaction.notes.rate_limit_type = 'inbox_day';
        return next(DENY, 'Daily rate limit exceeded for this address.');
    }
    
    // Use token if minute limit reached but tokens available
    if (inboxData.minuteCount >= RATE_LIMITS.per_minute && inboxData.tokens > 0) {
        inboxData.tokens--;
        plugin.loginfo(`Using burst token for ${recipient}, ${inboxData.tokens} remaining`);
    }
    
    // Increment all counters
    inboxData.minuteCount++;
    inboxData.hourCount++;
    inboxData.dayCount++;
    
    ipData.minuteCount++;
    ipData.hourCount++;
    
    // Store rate limit info in transaction notes for logging
    connection.transaction.notes.rate_limit_status = {
        inbox: recipient,
        minute: inboxData.minuteCount,
        hour: inboxData.hourCount,
        day: inboxData.dayCount,
        tokens: inboxData.tokens,
        ip: hashIP(normalizedIP),
        ip_minute: ipData.minuteCount,
        ip_hour: ipData.hourCount
    };
    
    return next(OK);
};

// Hook to check connection-level rate limits
exports.hook_connect = function(next, connection) {
    const plugin = this;
    const rawIP = connection.remote.ip;
    const normalizedIP = normalizeIPv6(rawIP);
    
    // Simple connection rate limiting
    const ipKey = `conn:${normalizedIP}`;
    let ipData = ipRateStore.get(ipKey);
    
    if (!ipData) {
        ipData = {
            connections: 0,
            lastReset: Date.now()
        };
        ipRateStore.set(ipKey, ipData);
    }
    
    // Reset every hour
    if (Date.now() - ipData.lastReset > 3600000) {
        ipData.connections = 0;
        ipData.lastReset = Date.now();
    }
    
    ipData.connections++;
    
    // Max 100 connections per hour per IP/subnet
    if (ipData.connections > 100) {
        plugin.logwarn(`Connection rate limit exceeded for IP ${hashIP(normalizedIP)}`);
        return next(DENYDISCONNECT, 'Too many connections. Please try again later.');
    }
    
    return next(OK);
};

// Hook to add rate limit headers to DATA
exports.hook_data = function(next, connection) {
    const status = connection.transaction.notes.rate_limit_status;
    if (status) {
        // Add custom headers for monitoring
        connection.transaction.add_header('X-RateLimit-Minute', `${status.minute}/${RATE_LIMITS.per_minute}`);
        connection.transaction.add_header('X-RateLimit-Hour', `${status.hour}/${RATE_LIMITS.per_hour}`);
        connection.transaction.add_header('X-RateLimit-Day', `${status.day}/${RATE_LIMITS.per_day}`);
        connection.transaction.add_header('X-RateLimit-Burst', `${status.tokens}/${RATE_LIMITS.burst}`);
    }
    
    return next();
};
