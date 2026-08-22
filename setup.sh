#!/bin/bash

# SpamEater Setup Script - Optimized Version
# Uses external config files to reduce script size

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


banner "v4 setup"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "${S_ERR} This script needs to run as root!"
   exit 1
fi

# Collect configuration
echo -e "\n${S_ARROW} Configuration Setup"
read -p "${S_ARROW} Enter your email domain (e.g., example.com): " EMAIL_DOMAIN

if [[ -z "$EMAIL_DOMAIN" ]]; then
    echo "${S_ERR} Email domain is required!"
    exit 1
fi

echo -e "\n${S_ARROW} Web Access Configuration"
echo "By default, the web interface will be accessible at: $EMAIL_DOMAIN"
echo "You can optionally use a different subdomain for privacy (e.g., mail.$EMAIL_DOMAIN)"
read -p "Enter web access domain (press Enter to use $EMAIL_DOMAIN): " WEB_DOMAIN

WEB_DOMAIN="${WEB_DOMAIN:-$EMAIL_DOMAIN}"

echo -e "\n${S_ARROW} Email Domain: $EMAIL_DOMAIN (emails will be received at @$EMAIL_DOMAIN)"
echo "${S_ARROW} Web Access: https://$WEB_DOMAIN"
read -p "Is this correct? (Y/n): " CONFIRM

if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
    echo "${S_ERR} Setup cancelled"
    exit 1
fi

# Generate credentials
ADMIN_EMAIL="admin@$EMAIL_DOMAIN"
# openssl rand -hex 16 always yields exactly 32 chars of full entropy
DELETE_TOKEN_SECRET=$(openssl rand -hex 16)
CSRF_SECRET=$(openssl rand -hex 16)
ENCRYPTION_KEY=$(openssl rand -hex 16)

echo -e "\n${S_OK} Generated credentials and secrets"

# Create dedicated user
echo "${S_ARROW} Creating spameater user..."
useradd -r -s /bin/false -d /opt/spameater spameater 2>/dev/null || echo "User already exists"

# Store the original script directory
ORIGINAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect OS and install dependencies
echo -e "\n${S_ARROW} Installing system dependencies..."
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
    echo "   Detected: RHEL/Fedora-based system (dnf)"
    echo -n "   ├─ Updating package cache... "
    dnf update -y -q && echo "${S_OK}"
    echo -n "   ├─ Adding Node.js 22 repository... "
    curl -fsSL https://rpm.nodesource.com/setup_22.x | bash - >/dev/null 2>&1 && echo "${S_OK}"
    echo -n "   ├─ Installing: nodejs nginx sqlite certbot fail2ban firewalld... "
    dnf install -y nodejs nginx sqlite certbot python3-certbot-nginx fail2ban firewalld -q && echo "${S_OK}"
    echo -n "   ├─ Installing: Development Tools (gcc, make, etc.)... "
    dnf groupinstall -y "Development Tools" -q && echo "${S_OK}"
    echo -n "   ├─ Installing: python3-devel sqlite-devel... "
    dnf install -y python3-devel sqlite-devel -q && echo "${S_OK}"
    echo -n "   ├─ Installing: ModSecurity WAF... "
    dnf install -y nginx-mod-modsecurity libmodsecurity mod_security_crs -q 2>/dev/null && echo "${S_OK}" || echo "${S_WARN} not available"
    echo -n "   └─ Enabling firewalld... "
    systemctl enable --now firewalld >/dev/null 2>&1 && echo "${S_OK}"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
    echo "   Detected: CentOS/RHEL 7 (yum)"
    echo -n "   ├─ Updating package cache... "
    yum update -y -q && echo "${S_OK}"
    echo -n "   ├─ Installing EPEL repository... "
    yum install -y epel-release -q && echo "${S_OK}"
    echo -n "   ├─ Adding Node.js 22 repository... "
    curl -fsSL https://rpm.nodesource.com/setup_22.x | bash - >/dev/null 2>&1 && echo "${S_OK}"
    echo -n "   ├─ Installing: nodejs nginx sqlite certbot fail2ban firewalld... "
    yum install -y nodejs nginx sqlite certbot python2-certbot-nginx fail2ban firewalld -q && echo "${S_OK}"
    echo -n "   ├─ Installing: Development Tools (gcc, make, etc.)... "
    yum groupinstall -y "Development Tools" -q && echo "${S_OK}"
    echo -n "   ├─ Installing: python3-devel sqlite-devel... "
    yum install -y python3-devel sqlite-devel -q && echo "${S_OK}"
    echo -n "   ├─ Installing: ModSecurity WAF... "
    yum install -y mod_security mod_security_crs -q 2>/dev/null && echo "${S_OK}" || echo "${S_WARN} not available"
    echo -n "   └─ Enabling firewalld... "
    systemctl enable --now firewalld >/dev/null 2>&1 && echo "${S_OK}"
else
    PKG_MGR="apt"
    echo "   Detected: Debian/Ubuntu-based system (apt)"
    echo -n "   ├─ Updating package cache... "
    apt update -qq && echo "${S_OK}"
    echo -n "   ├─ Adding Node.js 22 repository... "
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1 && echo "${S_OK}"
    echo -n "   ├─ Installing: nodejs nginx sqlite3 certbot fail2ban ufw... "
    apt install -y nodejs nginx sqlite3 certbot python3-certbot-nginx fail2ban ufw -qq && echo "${S_OK}"
    echo -n "   ├─ Installing: build-essential python3-dev libsqlite3-dev... "
    apt install -y build-essential python3-dev libsqlite3-dev -qq && echo "${S_OK}"
    echo -n "   └─ Installing: ModSecurity WAF... "
    apt install -y libnginx-mod-modsecurity libmodsecurity3 libmodsecurity-dev -qq 2>/dev/null && echo "${S_OK}" || echo "${S_WARN} not available"
fi

# Verify Node.js version
NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 22 ]; then
    echo "${S_ERR} Node.js version $NODE_VERSION is too old. Please install Node.js 22 LTS."
    exit 1
fi

echo "${S_OK} Node.js $(node --version), npm $(npm --version 2>/dev/null)"

# Create directory structure
echo -e "\n${S_ARROW} Setting up directories..."
mkdir -p /opt/spameater/{haraka,frontend,data,logs,modsecurity}
mkdir -p /opt/spameater/data/inboxes
mkdir -p /opt/spameater/haraka/queue
mkdir -p /opt/spameater/frontend/.well-known
chown -R spameater:spameater /opt/spameater
chmod 755 /opt/spameater
chmod 755 /opt/spameater/data

# Create environment file
cat > /opt/spameater/.env << EOF
DELETE_TOKEN_SECRET=$DELETE_TOKEN_SECRET
CSRF_SECRET=$CSRF_SECRET
ENCRYPTION_KEY=$ENCRYPTION_KEY
NODE_ENV=production
EOF
chown spameater:spameater /opt/spameater/.env
chmod 600 /opt/spameater/.env

# Setup database
echo "${S_ARROW} Setting up database..."
sudo -u spameater sqlite3 /opt/spameater/data/emails.db < "$ORIGINAL_DIR/database/schema.sql" >/dev/null 2>&1
chmod 600 /opt/spameater/data/emails.db

# Install Haraka
echo -e "\n${S_ARROW} Installing Haraka..."
npm install -g Haraka@3.3.3 --loglevel=error 2>/dev/null

# Initialize Haraka
cd /opt/spameater/haraka
sudo -u spameater haraka -i /opt/spameater/haraka >/dev/null 2>&1

# Install npm dependencies
echo -e "\n${S_ARROW} Installing npm dependencies..."
mkdir -p /tmp/spameater-npm-cache
chown -R spameater:spameater /tmp/spameater-npm-cache

# Install for Haraka
echo -n "   ├─ Haraka plugins: sqlite3 isomorphic-dompurify... "
cd /opt/spameater/haraka
sudo -u spameater npm install sqlite3@5.1.7 isomorphic-dompurify@3.22.0 --cache /tmp/spameater-npm-cache --unsafe-perm --loglevel=error 2>/dev/null && echo "${S_OK}" || echo "${S_WARN} failed"

# Install for API server
echo -n "   └─ API server: express helmet express-rate-limit sqlite3... "
cd /opt/spameater
sudo -u spameater npm install express@5.2.1 helmet@8.3.0 express-rate-limit@8.6.2 sqlite3@5.1.7 --cache /tmp/spameater-npm-cache --unsafe-perm --loglevel=error 2>/dev/null && echo "${S_OK}" || echo "${S_WARN} failed"

# sqlite3 stays on 5.1.7: its prebuilt binaries load on every supported OS
# (6.x prebuilds require glibc 2.38+, newer than RHEL 9, Ubuntu 22.04, and
# Debian 11 ship, and would force a from-source compile at install time).
echo -e "\n${S_ARROW} Verifying sqlite3 native binding..."
for APP_DIR in /opt/spameater/haraka /opt/spameater; do
    if sudo -u spameater node -e "require('$APP_DIR/node_modules/sqlite3')" >/dev/null 2>&1; then
        echo "   ├─ $APP_DIR: ${S_OK}"
    else
        echo "   ├─ $APP_DIR: ${S_WARN} sqlite3 binding failed to load"
    fi
done

# Copy all files
echo -e "\n${S_ARROW} Copying application files..."

# Copy Haraka config files
cp "$ORIGINAL_DIR/haraka/config/"*.ini /opt/spameater/haraka/config/
cp "$ORIGINAL_DIR/haraka/config/plugins" /opt/spameater/haraka/config/

# Process Haraka templates
sed "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" "$ORIGINAL_DIR/haraka/config/me.template" > /opt/spameater/haraka/config/me
sed "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" "$ORIGINAL_DIR/haraka/config/host_list.template" > /opt/spameater/haraka/config/host_list

# Copy Haraka plugins
cp "$ORIGINAL_DIR/haraka/plugins/"*.js /opt/spameater/haraka/plugins/

# Copy frontend files
cp -r "$ORIGINAL_DIR/frontend/"* /opt/spameater/frontend/

# Process frontend templates
sed -i "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" /opt/spameater/frontend/index.html

# Process security.txt
if [ -f "/opt/spameater/frontend/.well-known/security.txt.template" ]; then
    EXPIRY_DATE=$(date -d "+1 year" -u +"%Y-%m-%dT%H:%M:%S.000Z")
    sed -e "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" \
        -e "s/EXPIRY_DATE_PLACEHOLDER/$EXPIRY_DATE/g" \
        /opt/spameater/frontend/.well-known/security.txt.template > /opt/spameater/frontend/.well-known/security.txt
    rm -f /opt/spameater/frontend/.well-known/security.txt.template
fi

# Copy other files
cp "$ORIGINAL_DIR/api-server.js" /opt/spameater/
mkdir -p /opt/spameater/lib
cp "$ORIGINAL_DIR/lib/"*.js /opt/spameater/lib/
cp "$ORIGINAL_DIR/deploy/cleanup.sh" /opt/spameater/
chmod +x /opt/spameater/cleanup.sh /opt/spameater/api-server.js

# Setup ModSecurity
echo -e "\n${S_ARROW} Setting up ModSecurity WAF..."
MODSEC_ENABLED=false

if [ -f "/etc/nginx/modules/ngx_http_modsecurity_module.so" ] || \
   [ -f "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so" ] || \
   [ -f "/usr/share/nginx/modules/mod-modsecurity.conf" ]; then
    
    echo "${S_OK} ModSecurity module detected"
    cd /opt/spameater/modsecurity
    
    # Download unicode mapping
    wget -q https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping 2>/dev/null || \
    curl -s -o unicode.mapping https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping 2>/dev/null
    
    # Download OWASP CRS if not exists
    if [ ! -d "crs" ]; then
        git clone https://github.com/coreruleset/coreruleset.git crs --quiet
        cd crs && cp crs-setup.conf.example crs-setup.conf
    fi
    
    # Copy ModSecurity configs
    cp "$ORIGINAL_DIR/deploy/modsecurity-main.conf" /opt/spameater/modsecurity/modsecurity.conf
    cp "$ORIGINAL_DIR/deploy/modsecurity-rules.conf" /opt/spameater/modsecurity/spameater-rules.conf
    cp "$ORIGINAL_DIR/deploy/nginx-modsecurity.conf" /opt/spameater/modsecurity/
    
    if [ -f "/opt/spameater/modsecurity/unicode.mapping" ] && [ -d "/opt/spameater/modsecurity/crs/rules" ]; then
        MODSEC_ENABLED=true
        echo "${S_OK} ModSecurity configuration complete"
    fi
fi

cd "$ORIGINAL_DIR"

# Set ownership
chown -R spameater:spameater /opt/spameater/haraka /opt/spameater/frontend /opt/spameater/data

# Configure nginx rate limiting
echo -e "\n${S_ARROW} Configuring nginx..."
if ! grep -q "zone=api_limit" /etc/nginx/nginx.conf; then
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Insert rate limiting configuration
    sed -i "/^http {/r $ORIGINAL_DIR/deploy/nginx-rate-limits.conf" /etc/nginx/nginx.conf
fi

# Stop nginx and clean configs
systemctl stop nginx 2>/dev/null || true
find /etc/nginx -name "*spameater*" -delete 2>/dev/null || true

# Detect nginx config directory
if [ -d "/etc/nginx/sites-available" ]; then
    NGINX_SITES_DIR="/etc/nginx/sites-available"
    NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
else
    NGINX_SITES_DIR="/etc/nginx/conf.d"
    NGINX_ENABLED_DIR="/etc/nginx/conf.d"
fi

# Determine if subdomain
IS_SUBDOMAIN=false
[[ "$WEB_DOMAIN" == *"."*"."* ]] && IS_SUBDOMAIN=true

# Create nginx config
cp "$ORIGINAL_DIR/deploy/nginx.conf" /tmp/spameater.conf

# Remove SSL sections for initial setup
sed -i '/^server {.*listen 443/,/^}/d' /tmp/spameater.conf

# Replace placeholders - ORDER MATTERS!
sed -i "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" /tmp/spameater.conf
sed -i "s/DOMAIN_PLACEHOLDER/$WEB_DOMAIN/g" /tmp/spameater.conf

# Remove www for subdomains
if [ "$IS_SUBDOMAIN" = true ]; then
    sed -i "s/server_name $WEB_DOMAIN www.$WEB_DOMAIN;/server_name $WEB_DOMAIN;/g" /tmp/spameater.conf
fi

# Add ModSecurity if enabled
if [ "$MODSEC_ENABLED" = true ] && nginx -V 2>&1 | grep -q "modsecurity"; then
    sed -i '/location \/ {/i\    # ModSecurity WAF\n    include /opt/spameater/modsecurity/nginx-modsecurity.conf;\n' /tmp/spameater.conf
fi

# Install nginx config
if [ "$NGINX_SITES_DIR" = "/etc/nginx/conf.d" ]; then
    mv /tmp/spameater.conf /etc/nginx/conf.d/spameater.conf
else
    mv /tmp/spameater.conf $NGINX_SITES_DIR/spameater
    ln -sf $NGINX_SITES_DIR/spameater $NGINX_ENABLED_DIR/
fi

# Test and start nginx
nginx -t && systemctl start nginx || echo "${S_ERR} nginx configuration error"

# Configure systemd services
echo -e "\n${S_ARROW} Setting up systemd services..."
cp "$ORIGINAL_DIR/deploy/haraka.service" /etc/systemd/system/
cp "$ORIGINAL_DIR/deploy/spameater-api.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable haraka spameater-api

# Configure firewall
echo -e "\n${S_ARROW} Configuring firewall..."
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oP ':\K[0-9]+' | head -1)
    SSH_PORT="${SSH_PORT:-22}"
    
    firewall-cmd --permanent --add-service=smtp
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    [ "$SSH_PORT" != "22" ] && firewall-cmd --permanent --add-port=${SSH_PORT}/tcp || firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oP ':\K[0-9]+' | head -1)
    SSH_PORT="${SSH_PORT:-22}"
    
    ufw allow 25/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    [ "$SSH_PORT" != "22" ] && ufw allow ${SSH_PORT}/tcp || ufw allow ssh
else
    echo "${S_WARN} No active firewall detected!"
fi

# Configure fail2ban
echo -e "\n${S_ARROW} Setting up fail2ban..."
cp "$ORIGINAL_DIR/deploy/jail.local" /etc/fail2ban/
systemctl enable fail2ban
systemctl restart fail2ban

# SSL setup
echo -e "\n${S_ARROW} Setting up SSL certificates..."
mkdir -p /var/www/html/.well-known/acme-challenge

# Determine SSL domains
CERT_DOMAINS="-d $WEB_DOMAIN"
[ "$IS_SUBDOMAIN" = false ] && CERT_DOMAINS="$CERT_DOMAINS -d www.$WEB_DOMAIN"

SSL_CONFIGURED=false
if [ -d "/etc/letsencrypt/live/$WEB_DOMAIN" ]; then
    echo "${S_OK} SSL certificates already exist"
    certbot --nginx $CERT_DOMAINS --reinstall --redirect --non-interactive 2>/dev/null && SSL_CONFIGURED=true
else
    echo "Creating new SSL certificates..."
    read -p "Proceed with certificate creation? (Y/n): " CREATE_CERTS
    
    if [[ ! "$CREATE_CERTS" =~ ^[Nn]$ ]]; then
        certbot --nginx $CERT_DOMAINS --email "$ADMIN_EMAIL" --agree-tos --non-interactive --redirect && SSL_CONFIGURED=true
    fi
fi

# Re-add ModSecurity AFTER SSL setup (if it was enabled earlier)
if [ "$MODSEC_ENABLED" = true ]; then
    echo "${S_ARROW} Re-adding ModSecurity after SSL setup..."
    
    # Determine which nginx config file to update
    if [ "$NGINX_SITES_DIR" = "/etc/nginx/conf.d" ]; then
        NGINX_CONFIG="/etc/nginx/conf.d/spameater.conf"
    else
        NGINX_CONFIG="/etc/nginx/sites-available/spameater"
    fi
    
    # Add ModSecurity include after server_tokens off line (ONLY IF NOT ALREADY PRESENT)
    if [ -f "$NGINX_CONFIG" ] && grep -q "server_tokens off;" "$NGINX_CONFIG" ] && ! grep -q "modsecurity" "$NGINX_CONFIG"; then
        sed -i '/server_tokens off;/a\    \n    # ModSecurity WAF\n    include /opt/spameater/modsecurity/nginx-modsecurity.conf;' "$NGINX_CONFIG"
        
        # Test and reload nginx
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx
            echo "${S_OK} ModSecurity re-enabled after SSL setup"
        fi
    fi
fi

# Setup cron jobs
echo -e "\n${S_ARROW} Setting up cleanup job..."
crontab -u spameater -l 2>/dev/null | grep -v "cleanup.sh" | crontab -u spameater -
(crontab -u spameater -l 2>/dev/null; echo "0 * * * * /opt/spameater/cleanup.sh") | crontab -u spameater -

[ "$SSL_CONFIGURED" = true ] && \
    (crontab -l 2>/dev/null | grep -v "certbot renew"; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -

# Start services
echo -e "\n${S_ARROW} Starting services..."
systemctl restart nginx
systemctl start haraka
systemctl start spameater-api

# Check services are running
if systemctl is-active --quiet haraka; then
    echo "${S_OK} Haraka SMTP server: Running"
else
    echo "${S_ERR} Haraka SMTP server: Failed to start"
fi

if systemctl is-active --quiet spameater-api; then
    echo "${S_OK} SpamEater API: Running"
else
    echo "${S_ERR} SpamEater API: Failed to start"
fi

if systemctl is-active --quiet nginx; then
    echo "${S_OK} Nginx web server: Running"
else
    echo "${S_ERR} Nginx web server: Failed to start"
fi

# Final message
banner "installed"
echo "  ${C_DIM}email domain${C_RESET}   $EMAIL_DOMAIN"
if [ "$SSL_CONFIGURED" = true ]; then
    echo "  ${C_DIM}web access${C_RESET}     https://$WEB_DOMAIN"
else
    echo "  ${C_DIM}web access${C_RESET}     http://$WEB_DOMAIN ${S_WARN} SSL not configured"
fi
echo "  ${C_DIM}admin email${C_RESET}    $ADMIN_EMAIL"
if [ "$MODSEC_ENABLED" = true ]; then
    echo "  ${C_DIM}modsecurity${C_RESET}    enabled"
else
    echo "  ${C_DIM}modsecurity${C_RESET}    disabled"
fi
echo "  ${C_DIM}secrets${C_RESET}        /opt/spameater/.env (mode 600)"
echo ""
echo "${S_WARN} IMPORTANT: Save the credentials above!"
echo ""

# Get server's public IP (try multiple methods)
SERVER_IP=""
if command -v curl >/dev/null 2>&1; then
    SERVER_IP=$(curl -s -4 --connect-timeout 5 ifconfig.me 2>/dev/null)
fi
if [ -z "$SERVER_IP" ] && command -v wget >/dev/null 2>&1; then
    SERVER_IP=$(wget -qO- --timeout=5 ifconfig.me 2>/dev/null)
fi
if [ -z "$SERVER_IP" ]; then
    # Fallback to primary network interface IP
    SERVER_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
SERVER_IP="${SERVER_IP:-[YOUR_SERVER_IP]}"

echo "${S_ARROW} DNS Configuration Required:"
echo "1. MX record: $EMAIL_DOMAIN → 10 $EMAIL_DOMAIN"
echo "2. A record: $EMAIL_DOMAIN → $SERVER_IP"
if [[ "$WEB_DOMAIN" != "$EMAIL_DOMAIN" ]]; then
    echo "3. A record: $WEB_DOMAIN → $SERVER_IP"
fi
echo ""
echo "${S_ARROW} Service commands:"
echo "   systemctl status haraka"
echo "   systemctl status nginx"
echo "   systemctl status spameater-api"
echo ""
echo "${S_ARROW} Logs:"
echo "   journalctl -u haraka -f"
echo "   journalctl -u spameater-api -f"
echo "   tail -f /var/log/nginx/access.log"
