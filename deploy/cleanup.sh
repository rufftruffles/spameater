#!/bin/bash

# SpamEater Cleanup Script - Security Enhanced
# Runs hourly via cron to maintain system health and security

set -e  # Exit on any error

# Configuration
DB_PATH="/opt/spameater/data/emails.db"
DATA_DIR="/opt/spameater/data/inboxes"
LOG_DIR="/opt/spameater/logs"
LOG_FILE="$LOG_DIR/cleanup.log"
SECURITY_LOG_FILE="$LOG_DIR/security.log"
MAX_LOG_SIZE=10485760  # 10MB
MAX_DB_SIZE=104857600  # 100MB
MAX_JSON_FILES=1000
MAX_EMAIL_AGE=86400    # 24 hours in seconds

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Security logging function
security_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SECURITY] $1" | tee -a "$SECURITY_LOG_FILE"
}

# Portable file size function
get_file_size() {
    local file=$1
    if command -v stat >/dev/null 2>&1; then
        # Try GNU stat first (Linux)
        stat -c%s "$file" 2>/dev/null || \
        # Fall back to BSD stat (macOS)
        stat -f%z "$file" 2>/dev/null || \
        echo "0"
    else
        # Fallback using ls
        ls -l "$file" 2>/dev/null | awk '{print $5}' || echo "0"
    fi
}

# Security: Check if running as spameater user
if [[ "$(whoami)" != "spameater" ]]; then
    security_log "ERROR: Cleanup script attempted to run as $(whoami) instead of spameater"
    echo "ERROR: Cleanup script must run as spameater user" >&2
    exit 1
fi

# Security: Validate critical paths exist
if [[ ! -f "$DB_PATH" ]]; then
    log "ERROR: Database not found at $DB_PATH"
    exit 1
fi

if [[ ! -d "$DATA_DIR" ]]; then
    log "ERROR: Data directory not found at $DATA_DIR"
    exit 1
fi

# Security: Check file permissions
DB_PERMS=$(stat -c "%a" "$DB_PATH" 2>/dev/null || stat -f "%OLp" "$DB_PATH" 2>/dev/null)
if [[ "$DB_PERMS" != "600" ]]; then
    security_log "WARNING: Database permissions are $DB_PERMS, should be 600"
fi

log "Starting SpamEater cleanup process..."

# 1. Clean expired inboxes and emails from database
log "Cleaning expired data from database..."

# First, log security events for expired emails
sqlite3 "$DB_PATH" << 'EOF'
-- Log expired inboxes to security events before deletion
INSERT INTO security_events (event_type, event_data, timestamp)
SELECT 
    'expired_inbox',
    json_object('email', email_address, 'created_at', created_at, 'email_count', 
        (SELECT COUNT(*) FROM emails WHERE inbox_id = inboxes.id)),
    strftime('%s', 'now')
FROM inboxes 
WHERE expires_at < strftime('%s', 'now');
EOF

# Now perform the cleanup
CLEANUP_RESULT=$(sqlite3 "$DB_PATH" << 'EOF'
BEGIN TRANSACTION;

-- Count before cleanup
.mode line
SELECT 'Emails before cleanup: ' || COUNT(*) FROM emails;
SELECT 'Inboxes before cleanup: ' || COUNT(*) FROM inboxes;

-- Delete expired inboxes (CASCADE will handle related emails)
DELETE FROM inboxes WHERE expires_at < strftime('%s', 'now');

-- Delete orphaned emails (safety check)
DELETE FROM emails WHERE inbox_id NOT IN (SELECT id FROM inboxes);

-- Keep only latest 50 emails per inbox to prevent bloat
DELETE FROM emails WHERE id IN (
    SELECT e1.id FROM emails e1
    JOIN (
        SELECT inbox_id, id,
               ROW_NUMBER() OVER (PARTITION BY inbox_id ORDER BY received_at DESC) as rn
        FROM emails
    ) e2 ON e1.id = e2.id
    WHERE e2.rn > 50
);

-- Clean up old security events (keep 7 days)
DELETE FROM security_events
WHERE timestamp < strftime('%s', 'now', '-7 days');

-- Count after cleanup
SELECT 'Emails after cleanup: ' || COUNT(*) FROM emails;
SELECT 'Inboxes after cleanup: ' || COUNT(*) FROM inboxes;
SELECT 'Security events: ' || COUNT(*) FROM security_events;

COMMIT;

-- Optimize database (VACUUM must be outside transaction)
VACUUM;
ANALYZE;
EOF
)

if [[ $? -eq 0 ]]; then
    log "Database cleanup completed successfully"
    echo "$CLEANUP_RESULT" | while IFS= read -r line; do
        log "  $line"
    done
else
    security_log "ERROR: Database cleanup failed"
    exit 1
fi

# 2. Clean orphaned JSON files
log "Cleaning orphaned JSON files..."
json_cleaned=0
suspicious_files=0

if [[ -d "$DATA_DIR" ]]; then
    # Get list of valid email prefixes from database
    valid_prefixes=$(sqlite3 "$DB_PATH" "SELECT prefix FROM inboxes;" 2>/dev/null | sort)
    
    # Check each JSON file
    for json_file in "$DATA_DIR"/*.json; do
        if [[ -f "$json_file" ]]; then
            filename=$(basename "$json_file" .json)
            
            # Security: Validate filename format (alphanumeric, hyphens, underscores, dots only)
            if [[ ! "$filename" =~ ^[a-zA-Z0-9._-]+$ ]]; then
                security_log "Suspicious filename detected: $json_file"
                log "Removing invalid filename: $json_file"
                rm -f "$json_file"
                ((json_cleaned++))
                ((suspicious_files++))
                continue
            fi
            
            # Security: Check for path traversal attempts
            if [[ "$filename" =~ \.\. ]]; then
                security_log "Path traversal attempt in filename: $json_file"
                log "Removing dangerous filename: $json_file"
                rm -f "$json_file"
                ((json_cleaned++))
                ((suspicious_files++))
                continue
            fi
            
            # Check if prefix exists in database
            if ! echo "$valid_prefixes" | grep -q "^$filename$"; then
                log "Removing orphaned JSON: $json_file"
                rm -f "$json_file"
                ((json_cleaned++))
            fi
        fi
    done
    
    log "Cleaned $json_cleaned orphaned JSON files"
    if [[ $suspicious_files -gt 0 ]]; then
        security_log "Removed $suspicious_files suspicious files"
    fi
else
    log "WARNING: Data directory not found for JSON cleanup"
fi

# 3. Limit total JSON files (security against disk space attacks)
log "Checking JSON file count limits..."
json_count=$(find "$DATA_DIR" -name "*.json" -type f 2>/dev/null | wc -l)

if [[ $json_count -gt $MAX_JSON_FILES ]]; then
    security_log "WARNING: Too many JSON files ($json_count > $MAX_JSON_FILES)"
    log "WARNING: Too many JSON files ($json_count > $MAX_JSON_FILES), removing oldest..."
    
    # Remove oldest JSON files beyond limit
    find "$DATA_DIR" -name "*.json" -type f -printf '%T+ %p\n' 2>/dev/null | \
    sort | \
    head -n $((json_count - MAX_JSON_FILES)) | \
    cut -d' ' -f2- | \
    while IFS= read -r file; do
        log "Removing old JSON: $file"
        rm -f "$file"
    done
    
    log "Removed $((json_count - MAX_JSON_FILES)) oldest JSON files"
fi

# 4. Check database size and warn if too large
db_size=$(get_file_size "$DB_PATH")
if [[ $db_size -gt $MAX_DB_SIZE ]]; then
    security_log "WARNING: Database size ($db_size bytes) exceeds limit ($MAX_DB_SIZE bytes)"
    log "WARNING: Database size ($db_size bytes) exceeds limit ($MAX_DB_SIZE bytes)"
    
    # Emergency cleanup: Keep only last 1000 emails total
    sqlite3 "$DB_PATH" << 'EOF'
DELETE FROM emails WHERE id NOT IN (
    SELECT id FROM emails ORDER BY received_at DESC LIMIT 1000
);
VACUUM;
EOF
    
    log "Emergency cleanup: Reduced to latest 1000 emails"
    security_log "Emergency database cleanup performed"
fi

# 5. Rotate logs
log "Rotating log files..."

# Rotate cleanup log
if [[ -f "$LOG_FILE" ]]; then
    log_size=$(get_file_size "$LOG_FILE")
    if [[ $log_size -gt $MAX_LOG_SIZE ]]; then
        log "Rotating cleanup log file..."
        mv "$LOG_FILE" "${LOG_FILE}.old"
        # Keep only last old log
        rm -f "${LOG_FILE}.old.1"
    fi
fi

# Rotate security log
if [[ -f "$SECURITY_LOG_FILE" ]]; then
    security_log_size=$(get_file_size "$SECURITY_LOG_FILE")
    if [[ $security_log_size -gt $MAX_LOG_SIZE ]]; then
        security_log "Rotating security log file..."
        mv "$SECURITY_LOG_FILE" "${SECURITY_LOG_FILE}.old"
        # Keep only last old log
        rm -f "${SECURITY_LOG_FILE}.old.1"
    fi
fi

# 6. Clean temporary files
log "Cleaning temporary files..."
temp_cleaned=0

# Clean Haraka temp files older than 1 hour
if [[ -d "/tmp/haraka" ]]; then
    temp_cleaned=$(find /tmp/haraka -type f -mmin +60 2>/dev/null | wc -l)
    find /tmp/haraka -type f -mmin +60 -delete 2>/dev/null || true
fi

# Clean npm cache if it exists
if [[ -d "/tmp/spameater-npm-cache" ]]; then
    npm_cleaned=$(find /tmp/spameater-npm-cache -type f -mtime +1 2>/dev/null | wc -l)
    find /tmp/spameater-npm-cache -type f -mtime +1 -delete 2>/dev/null || true
    temp_cleaned=$((temp_cleaned + npm_cleaned))
fi

log "Cleaned $temp_cleaned temporary files"

# 7. Check for suspicious patterns in database
log "Checking for suspicious patterns..."
SUSPICIOUS_EMAILS=$(sqlite3 "$DB_PATH" << 'EOF'
SELECT COUNT(*) FROM emails 
WHERE sender LIKE '%<script%' 
   OR subject LIKE '%<script%'
   OR sender LIKE '%javascript:%'
   OR subject LIKE '%javascript:%';
EOF
)

if [[ $SUSPICIOUS_EMAILS -gt 0 ]]; then
    security_log "Found $SUSPICIOUS_EMAILS emails with suspicious content"
fi

# Check for rate limit violations in security events
RATE_LIMIT_VIOLATIONS=$(sqlite3 "$DB_PATH" << 'EOF'
SELECT COUNT(*) FROM security_events 
WHERE event_type = 'rate_limit' 
  AND timestamp > strftime('%s', 'now', '-1 hour');
EOF
)

if [[ $RATE_LIMIT_VIOLATIONS -gt 10 ]]; then
    security_log "High rate limit violations detected: $RATE_LIMIT_VIOLATIONS in last hour"
fi

# 8. System health check
log "Performing system health check..."

# Check disk space
disk_usage=$(df /opt/spameater | tail -1 | awk '{print $5}' | sed 's/%//')
if [[ $disk_usage -gt 90 ]]; then
    security_log "WARNING: Disk usage is ${disk_usage}%"
    log "WARNING: Disk usage is ${disk_usage}% - consider manual cleanup"
fi

# Check if Haraka is running
if ! systemctl is-active --quiet haraka; then
    security_log "WARNING: Haraka service is not running"
    log "WARNING: Haraka service is not running"
fi

# Check if API is running
if ! systemctl is-active --quiet spameater-api; then
    security_log "WARNING: SpamEater API service is not running"
    log "WARNING: SpamEater API service is not running"
fi

# Check if nginx is running
if ! systemctl is-active --quiet nginx; then
    security_log "WARNING: Nginx service is not running"
    log "WARNING: Nginx service is not running"
fi

# Check for failed systemd services
FAILED_SERVICES=$(systemctl list-units --failed --no-legend | wc -l)
if [[ $FAILED_SERVICES -gt 0 ]]; then
    security_log "WARNING: $FAILED_SERVICES failed systemd services detected"
fi

# 9. Generate summary statistics
log "Generating cleanup summary..."

# Get current statistics
STATS=$(sqlite3 "$DB_PATH" << 'EOF'
.mode line
SELECT 'Active inboxes: ' || COUNT(DISTINCT inbox_id) FROM emails WHERE received_at > strftime('%s', 'now', '-1 hour');
SELECT 'Emails last hour: ' || COUNT(*) FROM emails WHERE received_at > strftime('%s', 'now', '-1 hour');
SELECT 'Average email size: ' || ROUND(AVG(size_bytes)/1024.0, 2) || ' KB' FROM emails;
SELECT 'Total DB size: ' || ROUND(SUM(pgsize)/1024.0/1024.0, 2) || ' MB' FROM dbstat;
EOF
)

echo "$STATS" | while IFS= read -r line; do
    log "  $line"
done

# Final statistics
final_emails=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM emails;" 2>/dev/null || echo "0")
final_inboxes=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM inboxes;" 2>/dev/null || echo "0")
final_json=$(find "$DATA_DIR" -name "*.json" -type f 2>/dev/null | wc -l)
final_events=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM security_events;" 2>/dev/null || echo "0")

log "Cleanup completed - Emails: $final_emails, Inboxes: $final_inboxes, JSON files: $final_json, Security events: $final_events"
log "SpamEater cleanup process finished successfully"

# Write status file for monitoring
cat > "$LOG_DIR/cleanup.status" << EOF
{
  "last_run": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "success",
  "emails": $final_emails,
  "inboxes": $final_inboxes,
  "json_files": $final_json,
  "security_events": $final_events,
  "disk_usage": $disk_usage
}
EOF

exit 0
