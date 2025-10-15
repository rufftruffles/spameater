#!/bin/bash
# SpamEater Docker Build-Time Setup
# Non-interactive setup extracted from setup.sh

set -e  # Exit on error

echo "🍽️ SpamEater Docker Setup"
echo "========================"

BUILD_DIR="/tmp/spameater-build"
INSTALL_DIR="/opt/spameater"

# Check Node.js and npm
echo "📦 Checking Node.js and npm..."
node --version || exit 1
npm --version || exit 1

# Update npm
echo "📦 Updating npm..."
npm install -g npm@latest || echo "npm update failed, continuing"

# Install Haraka globally
echo "📦 Installing Haraka..."
npm install -g Haraka || exit 1

# Verify Haraka installation
which haraka || exit 1
echo "✅ Haraka installed successfully"

# Initialize Haraka
echo "🔨 Initializing Haraka..."
mkdir -p $INSTALL_DIR/haraka
cd $INSTALL_DIR/haraka
haraka -i . || exit 1
echo "✅ Haraka initialized"

# Install npm dependencies
echo "📚 Installing dependencies..."
mkdir -p /tmp/npm-cache

# Install for Haraka
cd $INSTALL_DIR/haraka
npm install sqlite3 --cache /tmp/npm-cache || exit 1

# Install for API server
cd $INSTALL_DIR
npm install express helmet express-rate-limit sqlite3 --cache /tmp/npm-cache || exit 1

# Copy application files
echo "📄 Copying application files..."

# API server and cleanup
cp $BUILD_DIR/api-server.js $INSTALL_DIR/
cp $BUILD_DIR/deploy/cleanup.sh $INSTALL_DIR/
chmod +x $INSTALL_DIR/cleanup.sh

# Frontend
cp -r $BUILD_DIR/frontend/* $INSTALL_DIR/frontend/

# Haraka configs
cp $BUILD_DIR/haraka/config/*.ini $INSTALL_DIR/haraka/config/ || true
cp $BUILD_DIR/haraka/config/plugins $INSTALL_DIR/haraka/config/
cp $BUILD_DIR/haraka/config/*.template $INSTALL_DIR/haraka/config/

# Haraka plugins
cp $BUILD_DIR/haraka/plugins/*.js $INSTALL_DIR/haraka/plugins/

# Setup database
echo "🗄️ Setting up database..."
if [ -f "$BUILD_DIR/database/schema.sql" ]; then
    sqlite3 $INSTALL_DIR/data/emails.db < $BUILD_DIR/database/schema.sql
    chmod 600 $INSTALL_DIR/data/emails.db
fi

# Setup ModSecurity
echo "🛡️ Setting up ModSecurity..."
cd $INSTALL_DIR/modsecurity

# Download unicode mapping
wget -q https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping || \
    curl -s -o unicode.mapping https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping || \
    echo "Could not download unicode.mapping"

# Clone OWASP CRS
if [ ! -d "crs" ]; then
    git clone https://github.com/coreruleset/coreruleset.git crs --quiet --depth=1 || \
        echo "Could not clone OWASP CRS"
    if [ -d "crs" ]; then
        cd crs && cp crs-setup.conf.example crs-setup.conf || true
    fi
fi

# Copy ModSecurity configs
cp $BUILD_DIR/deploy/modsecurity-main.conf $INSTALL_DIR/modsecurity/modsecurity.conf || true
cp $BUILD_DIR/deploy/modsecurity-rules.conf $INSTALL_DIR/modsecurity/spameater-rules.conf || true
cp $BUILD_DIR/deploy/nginx-modsecurity.conf $INSTALL_DIR/modsecurity/ || true

# Setup nginx
echo "🌐 Preparing nginx configuration..."
if [ -f "$BUILD_DIR/deploy/nginx-rate-limits.conf" ]; then
    if ! grep -q "zone=api_limit" /etc/nginx/nginx.conf; then
        cat $BUILD_DIR/deploy/nginx-rate-limits.conf > /tmp/rate-limits.conf
        sed -i '/^http {/r /tmp/rate-limits.conf' /etc/nginx/nginx.conf
    fi
fi

# Setup fail2ban
if [ -f "$BUILD_DIR/deploy/jail.local" ]; then
    cp $BUILD_DIR/deploy/jail.local /etc/fail2ban/
fi

# Setup cron
echo "0 * * * * spameater /opt/spameater/cleanup.sh" > /etc/cron.d/spameater-cleanup
chmod 644 /etc/cron.d/spameater-cleanup

# Fix permissions
chown -R spameater:spameater $INSTALL_DIR

# Cleanup
rm -rf /tmp/npm-cache

echo "✅ Docker build-time setup complete"
