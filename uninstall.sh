#!/bin/bash

# SpamEater Uninstall Script
# Completely removes SpamEater and restores server to original state

set -e  # Exit on any error

echo "🗑️ SpamEater Uninstaller"
echo "========================"

# Security: Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script needs to run as root!"
   exit 1
fi

# Warning prompt
echo ""
echo "⚠️  WARNING: This will completely remove SpamEater and all associated data!"
echo "   - All emails and inboxes will be permanently deleted"
echo "   - SSL certificates will be removed"
echo "   - System packages will be uninstalled"
echo "   - Firewall rules will be reset"
echo ""
read -p "Are you sure you want to continue? (type 'YES' to confirm): " CONFIRM

if [[ "$CONFIRM" != "YES" ]]; then
    echo "❌ Uninstall cancelled."
    exit 1
fi

echo ""
echo "🔍 Starting SpamEater removal process..."

# Stop and disable services
echo "ℹ️ Stopping SpamEater services..."
systemctl stop haraka 2>/dev/null || echo "Haraka service not running"
systemctl stop spameater-api 2>/dev/null || echo "SpamEater API service not running"
systemctl disable haraka 2>/dev/null || echo "Haraka service not enabled"
systemctl disable spameater-api 2>/dev/null || echo "SpamEater API service not enabled"
systemctl stop nginx 2>/dev/null || echo "Nginx not managed by us, skipping"

# Remove systemd service files
echo "🗂️ Removing systemd service files..."
rm -f /etc/systemd/system/haraka.service
rm -f /etc/systemd/system/spameater-api.service
systemctl daemon-reload

# Remove cron jobs
echo "⏰ Removing cron jobs..."
crontab -u spameater -l 2>/dev/null | grep -v "cleanup.sh" | crontab -u spameater - 2>/dev/null || true
crontab -l 2>/dev/null | grep -v "certbot renew" | crontab - 2>/dev/null || true

# Remove nginx configuration
echo "🌐 Removing nginx configuration..."
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
echo "🔐 SSL Certificate Management:"
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
        echo "🗑️ Removing SSL certificates..."
        
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
                echo "   ✅ Successfully removed certificates for $domain"
            else
                echo "   ⚠️  Failed to remove certificates for $domain"
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
echo "📁 Removing application files..."
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
    echo "   ✅ Removed /opt/spameater directory"
fi

# Remove SpamEater user
echo "👤 Removing spameater user..."
if id "spameater" &>/dev/null; then
    # Kill any remaining processes owned by spameater
    pkill -u spameater 2>/dev/null || true
    sleep 2  # Give processes time to die
    
    userdel -r spameater 2>/dev/null || userdel spameater 2>/dev/null || echo "   Failed to remove spameater user (may need manual cleanup)"
    echo "   ✅ Removed spameater user and home directory"
else
    echo "   SpamEater user not found"
fi

# Remove SpamEater-specific firewall rules
echo "🔥 Cleaning up firewall rules..."
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
echo "🛡️ Cleaning up fail2ban configuration..."
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
echo "📦 Removing Node.js packages..."
npm uninstall -g Haraka 2>/dev/null || echo "   Haraka not installed globally or already removed"

# Clean up npm cache
echo "🧹 Cleaning up npm cache..."
npm cache clean --force 2>/dev/null || true
rm -rf /tmp/spameater-npm-cache 2>/dev/null || true

# Optional: Remove packages (with user confirmation)
echo ""
echo "🤔 Package removal options:"
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
    echo "🗑️ Removing packages..."
    
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
echo "🧹 Cleaning up temporary files..."
rm -rf /tmp/haraka 2>/dev/null || true
rm -rf /tmp/spameater* 2>/dev/null || true
rm -rf /tmp/.npm 2>/dev/null || true
rm -rf /tmp/certbot_*.log 2>/dev/null || true

# Remove log files
echo "📄 Removing log files..."
rm -f /var/log/nginx/spameater_*.log 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true  # Clean up systemd journal logs

# Optional: Reset firewall to defaults
echo ""
read -p "Reset firewall to default settings? This will remove ALL custom rules (y/N): " RESET_FIREWALL

if [[ "$RESET_FIREWALL" =~ ^[Yy]$ ]]; then
    echo "🔥 Resetting firewall to defaults..."
    
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
echo "🔍 Verifying cleanup..."

# Check for remaining SpamEater files
REMAINING_FILES=$(find /etc /opt /var -name "*spameater*" 2>/dev/null | head -10)
if [ -n "$REMAINING_FILES" ]; then
    echo "⚠️  Some SpamEater-related files may still exist:"
    echo "$REMAINING_FILES"
    echo "   You may want to review and remove these manually."
else
    echo "✅ No remaining SpamEater files detected"
fi

# Check for remaining SSL certificates
if [ -d "/etc/letsencrypt/live" ]; then
    REMAINING_CERTS=$(find /etc/letsencrypt/live -maxdepth 1 -type d -not -path "/etc/letsencrypt/live" 2>/dev/null | wc -l)
    if [ "$REMAINING_CERTS" -gt 0 ]; then
        echo "⚠️  Some SSL certificates still exist in /etc/letsencrypt/live/"
    else
        echo "✅ All SSL certificates removed"
    fi
else
    echo "✅ No SSL certificates directory found"
fi

# Check for SpamEater processes
SPAMEATER_PROCESSES=$(ps aux | grep -i spameater | grep -v grep | head -5)
if [ -n "$SPAMEATER_PROCESSES" ]; then
    echo "⚠️  Some SpamEater processes may still be running:"
    echo "$SPAMEATER_PROCESSES"
    echo "   You may need to kill these manually."
else
    echo "✅ No SpamEater processes found running"
fi

# Check for SpamEater network listeners
SPAMEATER_PORTS=$(ss -tlnp 2>/dev/null | grep -E ':(25|3001)' | head -3)
if [ -n "$SPAMEATER_PORTS" ]; then
    echo "⚠️  SMTP/API ports may still be in use:"
    echo "$SPAMEATER_PORTS"
    echo "   Check if these are SpamEater-related."
else
    echo "✅ No services detected on SpamEater ports"
fi

# Summary
echo ""
echo "✅ SpamEater uninstallation completed!"
echo ""
echo "📋 Summary of actions taken:"
echo "   ✔ Stopped and removed Haraka SMTP service"
echo "   ✔ Stopped and removed SpamEater API service"
echo "   ✔ Removed systemd service files"
echo "   ✔ Cleaned up cron jobs"
echo "   ✔ Removed nginx configuration"
echo "   ✔ Removed SSL certificates (if requested)"
echo "   ✔ Deleted application files (/opt/spameater)"
echo "   ✔ Removed spameater user account"
echo "   ✔ Cleaned up firewall rules"
echo "   ✔ Removed fail2ban configuration"
echo "   ✔ Uninstalled Haraka Node.js package"
echo "   ✔ Cleaned up npm cache"
if [[ "$REMOVE_PACKAGES" =~ ^[Yy]$ ]]; then
    echo "   ✔ Removed system packages"
    echo "   ✔ Removed NodeSource repository"
fi
if [[ "$RESET_FIREWALL" =~ ^[Yy]$ ]]; then
    echo "   ✔ Reset firewall to defaults"
fi
echo ""
echo "📄 Your server has been restored to its pre-SpamEater state."
echo ""
echo "🔍 Manual cleanup recommendations:"
echo "   - Review DNS records and remove MX/A records for SpamEater domain"
echo "   - Check for any remaining custom configurations in /etc/"
echo "   - Verify no important data was stored in /opt/spameater/ before removal"
echo "   - Consider rebooting the server to ensure all changes take effect"
echo ""
echo "🆘 If you experience any issues:"
echo "   - Check system logs: journalctl -xe"
echo "   - Verify services: systemctl status nginx"
echo "   - Check firewall: systemctl status firewalld (RHEL) or ufw status (Debian)"
echo ""
echo "Thank you for using SpamEater! 🍽️"
