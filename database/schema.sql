-- SpamEater Database Schema - Security Enhanced
-- Minimal, secure SQLite schema for temporary email storage

-- Enable foreign key constraints for data integrity
PRAGMA foreign_keys = ON;

-- Enable Write-Ahead Logging for better concurrency
PRAGMA journal_mode = WAL;

-- Inboxes table - tracks created email addresses
CREATE TABLE IF NOT EXISTS inboxes (
    id TEXT PRIMARY KEY,                    -- UUID v4 for inbox ID
    email_address TEXT UNIQUE NOT NULL,     -- Full email (e.g., myname@domain.com)
    prefix TEXT NOT NULL,                   -- Just the prefix part (e.g., myname)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now', '+24 hours')),
    last_accessed INTEGER DEFAULT (strftime('%s', 'now')),
    -- Add constraints for better data integrity
    CHECK(length(email_address) <= 100),
    CHECK(length(prefix) <= 50)
);

-- Emails table - stores received emails with encryption support
CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY,                    -- UUID v4 for email ID
    inbox_id TEXT NOT NULL,                 -- Foreign key to inboxes
    sender TEXT NOT NULL,                   -- From address (plain for searching)
    sender_name TEXT,                       -- From display name (if available)
    sender_hash TEXT NOT NULL,              -- SHA256 hash of sender for indexing
    subject TEXT NOT NULL DEFAULT '',       -- Email subject (plain for searching)
    body_text_encrypted BLOB,               -- Encrypted plain text body
    body_html_encrypted BLOB,               -- Encrypted HTML body
    body_text_hash TEXT,                    -- Hash for duplicate detection
    received_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    message_id TEXT,                        -- Original Message-ID header
    size_bytes INTEGER DEFAULT 0,           -- Email size for cleanup
    
    -- Security metadata
    spf_result TEXT DEFAULT 'none',         -- SPF validation result
    dkim_result TEXT DEFAULT 'none',        -- DKIM validation result
    spam_score REAL DEFAULT 0.0,            -- Spam score if available
    
    FOREIGN KEY (inbox_id) REFERENCES inboxes(id) ON DELETE CASCADE,
    CHECK(size_bytes >= 0 AND size_bytes <= 10485760),  -- Max 10MB
    CHECK(spf_result IN ('none', 'pass', 'fail', 'softfail', 'neutral', 'temperror', 'permerror')),
    CHECK(dkim_result IN ('none', 'pass', 'fail', 'policy', 'neutral', 'temperror', 'permerror'))
);

-- Performance and security indexes
CREATE INDEX IF NOT EXISTS idx_inboxes_email ON inboxes(email_address);
CREATE INDEX IF NOT EXISTS idx_inboxes_expires ON inboxes(expires_at);
CREATE INDEX IF NOT EXISTS idx_inboxes_prefix ON inboxes(prefix);  -- For faster JSON lookups
CREATE INDEX IF NOT EXISTS idx_emails_inbox ON emails(inbox_id);
CREATE INDEX IF NOT EXISTS idx_emails_received ON emails(received_at);
CREATE INDEX IF NOT EXISTS idx_emails_sender_hash ON emails(sender_hash);  -- For sender analysis
CREATE INDEX IF NOT EXISTS idx_emails_hash ON emails(body_text_hash);  -- For duplicate detection

-- Security: Create view for public data access (no sensitive internals)
CREATE VIEW IF NOT EXISTS public_emails AS
SELECT 
    e.id,
    e.sender,
    e.sender_name,
    e.subject,
    e.received_at,
    e.size_bytes,
    e.spf_result,
    e.dkim_result,
    i.email_address,
    i.prefix
FROM emails e
JOIN inboxes i ON e.inbox_id = i.id
WHERE i.expires_at > strftime('%s', 'now');

-- Audit log table for security monitoring
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,               -- 'rate_limit', 'suspicious_pattern', 'auth_failure', etc.
    event_data TEXT,                        -- JSON data about the event
    ip_address TEXT,                        -- Source IP if applicable
    user_agent TEXT,                        -- User agent if applicable
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    CHECK(event_type IN ('rate_limit', 'suspicious_pattern', 'auth_failure', 'invalid_input', 'enumeration_attempt', 'expired_inbox'))
);

-- Index for security event queries
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip_address);

-- Cleanup trigger to maintain database size
CREATE TRIGGER IF NOT EXISTS cleanup_expired_inboxes
    AFTER INSERT ON emails
    WHEN (SELECT COUNT(*) FROM emails) % 100 = 0  -- Run every 100 insertions
BEGIN
    -- Delete expired inboxes and their emails (CASCADE handles emails)
    DELETE FROM inboxes 
    WHERE expires_at < strftime('%s', 'now');
    
    -- Keep database lean - delete oldest emails if we have too many
    DELETE FROM emails 
    WHERE id IN (
        SELECT id FROM emails 
        ORDER BY received_at ASC 
        LIMIT (SELECT MAX(0, COUNT(*) - 10000) FROM emails)
    );
    
    -- Clean up old security events (keep 7 days)
    DELETE FROM security_events 
    WHERE timestamp < strftime('%s', 'now', '-7 days');
END;

-- Add stored procedure for atomic inbox creation (prevents race condition)
-- Note: SQLite doesn't support stored procedures, so we'll handle this in application code
-- But we can use INSERT OR IGNORE pattern in the application
