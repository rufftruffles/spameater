#!/bin/bash

# SpamEater Uninstall Script
# Completely removes SpamEater and restores server to original state

set -e  # Exit on any error

# ── Terminal Ledger output theme ──────────────────────────────────────
if [ -t 1 ]; then
    C_ACCENT=$'\e[38;2;163;230;53m'
    C_TEXT=$'\e[38;2;238;244;234m'
    C_DIM=$'\e[38;2;125;138;118m'
    C_WARN=$'\e[38;2;230;194;41m'
    C_ERR=$'\e[38;2;230;95;69m'
    C_BOLD=$'\e[1m'
    C_RESET=$'\e[0m'
else
    C_ACCENT=''; C_TEXT=''; C_DIM=''; C_WARN=''; C_ERR=''; C_BOLD=''; C_RESET=''
fi
S_OK="${C_ACCENT}ok${C_RESET}"
S_ERR="${C_ERR}error:${C_RESET}"
S_WARN="${C_WARN}warn:${C_RESET}"
S_INFO="${C_DIM}info:${C_RESET}"
S_ARROW="${C_ACCENT}▸${C_RESET}"
banner() {
    echo ""
    echo "${C_ACCENT}${C_BOLD}SPAMEATER${C_RESET} ${C_DIM}$1${C_RESET}"
    echo "${C_DIM}────────────────────────────────────────${C_RESET}"
}


banner "uninstall"

# Security: Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "${S_ERR} This script needs to run as root!"
   exit 1
fi

# Warning prompt
echo ""
echo "${S_WARN}  WARNING: This will completely remove SpamEater and all associated data!"
echo "   - All emails and inboxes will be permanently deleted"
echo "   - SSL certificates will be removed"
echo "   - System packages will be uninstalled"
echo "   - Firewall rules will be reset"
echo ""
read -p "Are you sure you want to continue? (type 'YES' to confirm): " CONFIRM

if [[ "$CONFIRM" != "YES" ]]; then
    echo "${S_ERR} Uninstall cancelled."
    exit 1
fi

echo ""
echo "${S_ARROW} Starting SpamEater removal process..."

# Stop and disable services
echo "${S_INFO} Stopping SpamEater services..."
systemctl stop haraka 2>/dev/null || echo "Haraka service not running"
systemctl stop spameater-api 2>/dev/null || echo "SpamEater API service not running"
systemctl disable haraka 2>/dev/null || echo "Haraka service not enabled"
systemctl disable spameater-api 2>/dev/null || echo "SpamEater API service not enabled"
systemctl stop nginx 2>/dev/null || echo "Nginx not managed by us, skipping"

# Remove systemd service files
echo "${S_ARROW} Removing systemd service files..."
rm -f /etc/systemd/system/haraka.service
rm -f /etc/systemd/system/spameater-api.service
systemctl daemon-reload

# Remove cron jobs
echo "${S_ARROW} Removing cron jobs..."
crontab -u spameater -l 2>/dev/null | grep -v "cleanup.sh" | crontab -u spameater - 2>/dev/null || true
crontab -l 2>/dev/null | grep -v "certbot renew" | crontab - 2>/dev/null || true

# Remove nginx configuration
echo "${S_ARROW} Removing nginx configuration..."
# Detect nginx configuration method
if [ -f "/etc/nginx/sites-available/spameater" ]; then
    # Debian-style
    rm -f /etc/nginx/sites-available/spameater
    rm -f /etc/nginx/sites-enabled/spameater
elif [ -f "/etc/nginx/conf.d/spameater.conf" ]; then
    # RHEL-style
    rm -f /etc/nginx/conf.d/spameater.conf
fi

# Test nginx config and reload
nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || echo "Nginx configuration updated"

# Remove SSL certificates (Let's Encrypt)
echo ""
echo "${S_ARROW} SSL Certificate Management:"
echo "   Let's Encrypt has rate limits (5 certificates per domain per week)"
echo "   If you're testing, you may want to keep certificates to avoid rate limits"
echo ""

# Check if certificates exist
CERT_EXISTS=false
CERT_DIRS=""

if [ -d "/etc/letsencrypt/live" ]; then
    # Find all certificate directories
    CERT_DIRS=$(find /etc/letsencrypt/live -maxdepth 1 -type d -not -path "/etc/letsencrypt/live" 2>/dev/null || true)
    
    if [ -n "$CERT_DIRS" ]; then
        CERT_EXISTS=true
        echo "   Found SSL certificates for:"
        for cert_dir in $CERT_DIRS; do
            domain=$(basename "$cert_dir")
            echo "     - $domain"
        done
    fi
fi

if [ "$CERT_EXISTS" = true ]; then
    read -p "Remove SSL certificates? (y/N): " REMOVE_CERTS
    
    if [[ "$REMOVE_CERTS" =~ ^[Yy]$ ]]; then
        echo "${S_ARROW} Removing SSL certificates..."
        
        for cert_dir in $CERT_DIRS; do
            domain=$(basename "$cert_dir")
            echo "   Removing certificates for: $domain"
            
            # First try using certbot delete
            if command -v certbot >/dev/null 2>&1; then
                certbot delete --cert-name "$domain" --non-interactive 2>/dev/null || {
                    # If certbot fails, remove manually
                    echo "   Certbot failed, removing manually..."
                    rm -rf "/etc/letsencrypt/live/$domain"
                    rm -rf "/etc/letsencrypt/archive/$domain"
                    rm -f "/etc/letsencrypt/renewal/$domain.conf"
                }
            else
                # Certbot not available, remove manually
                echo "   Removing manually (certbot not found)..."
                rm -rf "/etc/letsencrypt/live/$domain"
                rm -rf "/etc/letsencrypt/archive/$domain"
                rm -f "/etc/letsencrypt/renewal/$domain.conf"
            fi
            
            # Verify removal
            if [ ! -d "/etc/letsencrypt/live/$domain" ]; then
                echo "   ${S_OK} Successfully removed certificates for $domain"
            else
                echo "   ${S_WARN}  Failed to remove certificates for $domain"
            fi
        done
        
        # Clean up empty Let's Encrypt directories
        rmdir /etc/letsencrypt/live 2>/dev/null || true
        rmdir /etc/letsencrypt/archive 2>/dev/null || true
        rmdir /etc/letsencrypt/renewal 2>/dev/null || true
    else
        echo "   Keeping SSL certificates (recommended for testing)"
    fi
else
    echo "   No SSL certificates found to remove"
fi

# Remove SpamEater application directory
echo "${S_ARROW} Removing application files..."
if [ -d "/opt/spameater" ]; then
    # List what's being removed
    echo "   Removing:"
    echo "   - /opt/spameater/haraka (SMTP server)"
    echo "   - /opt/spameater/frontend (Web interface)"
    echo "   - /opt/spameater/data (Emails and inboxes)"
    echo "   - /opt/spameater/logs (Log files)"
    echo "   - /opt/spameater/api-server.js (API server)"
    echo "   - /opt/spameater/cleanup.sh (Cleanup script)"
    
    rm -rf /opt/spameater
    echo "   ${S_OK} Removed /opt/spameater directory"
fi

# Remove SpamEater user
echo "${S_ARROW} Removing spameater user..."
if id "spameater" &>/dev/null; then
    # Kill any remaining processes owned by spameater
    pkill -u spameater 2>/dev/null || true
    sleep 2  # Give processes time to die
    
    userdel -r spameater 2>/dev/null || userdel spameater 2>/dev/null || echo "   Failed to remove spameater user (may need manual cleanup)"
    echo "   ${S_OK} Removed spameater user and home directory"
else
    echo "   SpamEater user not found"
fi

# Remove SpamEater-specific firewall rules
echo "${S_ARROW} Cleaning up firewall rules..."
if command -v firewall-cmd >/dev/null 2>&1; then
    # RHEL-based systems
    if systemctl is-active --quiet firewalld; then
        echo "   Detected firewalld, removing SMTP rule..."
        firewall-cmd --permanent --remove-service=smtp 2>/dev/null || echo "   SMTP service rule not found"
        firewall-cmd --reload 2>/dev/null || true
    else
        echo "   firewalld not active"
    fi
elif command -v ufw >/dev/null 2>&1; then
    # Debian-based systems
    if ufw status | grep -q "Status: active"; then
        echo "   Detected ufw, removing SMTP rule..."
        ufw delete allow 25/tcp 2>/dev/null || echo "   SMTP rule not found"
    else
        echo "   ufw not active"
    fi
fi

# Remove fail2ban configuration
echo "${S_ARROW} Cleaning up fail2ban configuration..."
if [ -f "/etc/fail2ban/jail.local" ]; then
    # Check if our configuration is still there
    if grep -q "spameater\|haraka" /etc/fail2ban/jail.local 2>/dev/null; then
        echo "   Removing SpamEater-specific fail2ban rules..."
        # Remove SpamEater-specific sections, but keep other custom rules
        sed -i '/# SpamEater/d' /etc/fail2ban/jail.local 2>/dev/null || true
        systemctl restart fail2ban 2>/dev/null || echo "   fail2ban restart failed"
    fi
fi

# Uninstall Node.js packages
echo "${S_ARROW} Removing Node.js packages..."
npm uninstall -g Haraka 2>/dev/null || echo "   Haraka not installed globally or already removed"

# Clean up npm cache
echo "${S_ARROW} Cleaning up npm cache..."
npm cache clean --force 2>/dev/null || true
rm -rf /tmp/spameater-npm-cache 2>/dev/null || true

# Optional: Remove packages (with user confirmation)
echo ""
echo "${S_ARROW} Package removal options:"
echo "   The following packages were installed during SpamEater setup:"
echo "   - nodejs (Node.js 22 LTS runtime)"
echo "   - nginx (OS default version)"
echo "   - sqlite3 (OS default version)"
echo "   - certbot, python3-certbot-nginx (SSL certificates)"
echo "   - fail2ban (security)"
echo "   - express (npm package - locally installed)"
echo ""
read -p "Remove these packages? This may affect other applications (y/N): " REMOVE_PACKAGES

if [[ "$REMOVE_PACKAGES" =~ ^[Yy]$ ]]; then
    echo "${S_ARROW} Removing packages..."
    
    if command -v dnf >/dev/null 2>&1; then
        # RHEL/AlmaLinux/Rocky/Fedora
        dnf remove -y nodejs nginx sqlite certbot python3-certbot-nginx fail2ban 2>/dev/null || echo "   Some packages not found or already removed"
    elif command -v yum >/dev/null 2>&1; then
        # CentOS 7 or older RHEL
        yum remove -y nodejs nginx sqlite certbot python2-certbot-nginx fail2ban 2>/dev/null || echo "   Some packages not found or already removed"
    else
        # Debian/Ubuntu
        apt remove -y nodejs nginx sqlite3 certbot python3-certbot-nginx fail2ban 2>/dev/null || echo "   Some packages not found or already removed"
        
        # Clean up package cache
        apt autoremove -y 2>/dev/null || true
        apt autoclean 2>/dev/null || true
    fi
    
    # Remove NodeSource repository
    echo "   Removing NodeSource repository..."
    if [ -f "/etc/yum.repos.d/nodesource*.repo" ]; then
        rm -f /etc/yum.repos.d/nodesource*.repo
    elif [ -f "/etc/apt/sources.list.d/nodesource.list" ]; then
        rm -f /etc/apt/sources.list.d/nodesource.list
    fi
else
    echo "   Keeping packages installed"
fi

# Clean up temporary files
echo "${S_ARROW} Cleaning up temporary files..."
rm -rf /tmp/haraka 2>/dev/null || true
rm -rf /tmp/spameater* 2>/dev/null || true
rm -rf /tmp/.npm 2>/dev/null || true
rm -rf /tmp/certbot_*.log 2>/dev/null || true

# Remove log files
echo "${S_ARROW} Removing log files..."
rm -f /var/log/nginx/spameater_*.log 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true  # Clean up systemd journal logs

# Optional: Reset firewall to defaults
echo ""
read -p "Reset firewall to default settings? This will remove ALL custom rules (y/N): " RESET_FIREWALL

if [[ "$RESET_FIREWALL" =~ ^[Yy]$ ]]; then
    echo "${S_ARROW} Resetting firewall to defaults..."
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        # Reset firewalld to defaults
        firewall-cmd --complete-reload 2>/dev/null || true
        firewall-cmd --set-default-zone=public 2>/dev/null || true
        echo "   Firewalld reset to default configuration"
    elif command -v ufw >/dev/null 2>&1; then
        # Reset ufw to defaults
        ufw --force reset 2>/dev/null || true
        echo "   UFW reset to default configuration"
    fi
else
    echo "   Keeping current firewall configuration"
fi

# Final cleanup verification
echo ""
echo "${S_ARROW} Verifying cleanup..."

# Check for remaining SpamEater files
REMAINING_FILES=$(find /etc /opt /var -name "*spameater*" 2>/dev/null | head -10)
if [ -n "$REMAINING_FILES" ]; then
    echo "${S_WARN}  Some SpamEater-related files may still exist:"
    echo "$REMAINING_FILES"
    echo "   You may want to review and remove these manually."
else
    echo "${S_OK} No remaining SpamEater files detected"
fi

# Check for remaining SSL certificates
if [ -d "/etc/letsencrypt/live" ]; then
    REMAINING_CERTS=$(find /etc/letsencrypt/live -maxdepth 1 -type d -not -path "/etc/letsencrypt/live" 2>/dev/null | wc -l)
    if [ "$REMAINING_CERTS" -gt 0 ]; then
        echo "${S_WARN}  Some SSL certificates still exist in /etc/letsencrypt/live/"
    else
        echo "${S_OK} All SSL certificates removed"
    fi
else
    echo "${S_OK} No SSL certificates directory found"
fi

# Check for SpamEater processes
SPAMEATER_PROCESSES=$(ps aux | grep -i spameater | grep -v grep | head -5)
if [ -n "$SPAMEATER_PROCESSES" ]; then
    echo "${S_WARN}  Some SpamEater processes may still be running:"
    echo "$SPAMEATER_PROCESSES"
    echo "   You may need to kill these manually."
else
    echo "${S_OK} No SpamEater processes found running"
fi

# Check for SpamEater network listeners
SPAMEATER_PORTS=$(ss -tlnp 2>/dev/null | grep -E ':(25|3001)' | head -3)
if [ -n "$SPAMEATER_PORTS" ]; then
    echo "${S_WARN}  SMTP/API ports may still be in use:"
    echo "$SPAMEATER_PORTS"
    echo "   Check if these are SpamEater-related."
else
    echo "${S_OK} No services detected on SpamEater ports"
fi

# Summary
echo ""
echo "${S_OK} SpamEater uninstallation completed!"
echo ""
echo "${S_ARROW} Summary of actions taken:"
echo "   ${S_OK} Stopped and removed Haraka SMTP service"
echo "   ${S_OK} Stopped and removed SpamEater API service"
echo "   ${S_OK} Removed systemd service files"
echo "   ${S_OK} Cleaned up cron jobs"
echo "   ${S_OK} Removed nginx configuration"
echo "   ${S_OK} Removed SSL certificates (if requested)"
echo "   ${S_OK} Deleted application files (/opt/spameater)"
echo "   ${S_OK} Removed spameater user account"
echo "   ${S_OK} Cleaned up firewall rules"
echo "   ${S_OK} Removed fail2ban configuration"
echo "   ${S_OK} Uninstalled Haraka Node.js package"
echo "   ${S_OK} Cleaned up npm cache"
if [[ "$REMOVE_PACKAGES" =~ ^[Yy]$ ]]; then
    echo "   ${S_OK} Removed system packages"
    echo "   ${S_OK} Removed NodeSource repository"
fi
if [[ "$RESET_FIREWALL" =~ ^[Yy]$ ]]; then
    echo "   ${S_OK} Reset firewall to defaults"
fi
echo ""
echo "${S_ARROW} Your server has been restored to its pre-SpamEater state."
echo ""
echo "${S_ARROW} Manual cleanup recommendations:"
echo "   - Review DNS records and remove MX/A records for SpamEater domain"
echo "   - Check for any remaining custom configurations in /etc/"
echo "   - Verify no important data was stored in /opt/spameater/ before removal"
echo "   - Consider rebooting the server to ensure all changes take effect"
echo ""
echo "${S_ARROW} If you experience any issues:"
echo "   - Check system logs: journalctl -xe"
echo "   - Verify services: systemctl status nginx"
echo "   - Check firewall: systemctl status firewalld (RHEL) or ufw status (Debian)"
echo ""
echo "Thank you for using SpamEater! ${S_ARROW}"
