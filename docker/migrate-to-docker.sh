#!/bin/bash
# SpamEater Migration Script
# Migrate from native installation to Docker

set -e

echo "🔄 SpamEater Docker Migration Tool"
echo "=================================="
echo ""
echo "This script will help you migrate from a native SpamEater installation"
echo "to the Docker version while preserving your data and certificates."
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script needs to run as root!"
   exit 1
fi

# Detect existing installation
if [ ! -d "/opt/spameater" ]; then
    echo "❌ No SpamEater installation found at /opt/spameater"
    echo "   This script is for migrating existing installations only."
    exit 1
fi

echo "✅ Found SpamEater installation at /opt/spameater"
echo ""

# Get domain information from existing config
if [ -f "/opt/spameater/haraka/config/me" ]; then
    EMAIL_DOMAIN=$(cat /opt/spameater/haraka/config/me)
    echo "📧 Detected email domain: $EMAIL_DOMAIN"
else
    read -p "Enter your email domain: " EMAIL_DOMAIN
fi

# Get web domain from nginx config if possible
if [ -f "/etc/nginx/sites-available/spameater" ] || [ -f "/etc/nginx/conf.d/spameater.conf" ]; then
    WEB_DOMAIN=$(grep server_name /etc/nginx/sites-available/spameater 2>/dev/null | head -1 | awk '{print $2}' | sed 's/;//')
    if [ -z "$WEB_DOMAIN" ]; then
        WEB_DOMAIN=$(grep server_name /etc/nginx/conf.d/spameater.conf 2>/dev/null | head -1 | awk '{print $2}' | sed 's/;//')
    fi
    echo "🌐 Detected web domain: $WEB_DOMAIN"
else
    WEB_DOMAIN=$EMAIL_DOMAIN
fi

# Get existing secrets from .env if available
if [ -f "/opt/spameater/.env" ]; then
    echo "🔐 Found existing secrets in .env file"
    source /opt/spameater/.env
fi

echo ""
echo "⚠️  WARNING: This migration will:"
echo "   1. Stop the native SpamEater services"
echo "   2. Backup your data and certificates"
echo "   3. Set up the Docker version"
echo "   4. Restore your data to the Docker containers"
echo ""
read -p "Do you want to continue? (yes/NO): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "❌ Migration cancelled"
    exit 1
fi

# Create migration directory
MIGRATION_DIR="/tmp/spameater-migration-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$MIGRATION_DIR"
echo "📁 Created migration directory: $MIGRATION_DIR"

# Stop native services
echo ""
echo "🛑 Stopping native SpamEater services..."
systemctl stop haraka 2>/dev/null || echo "Haraka not running"
systemctl stop spameater-api 2>/dev/null || echo "API not running"
systemctl stop nginx 2>/dev/null || echo "Nginx not managed by SpamEater"

# Backup data
echo ""
echo "💾 Backing up data..."
cp -r /opt/spameater/data "$MIGRATION_DIR/" 2>/dev/null || echo "No data directory"
echo "✅ Data backed up"

# Backup certificates
echo "🔒 Backing up SSL certificates..."
if [ -d "/etc/letsencrypt/live/$WEB_DOMAIN" ]; then
    tar czf "$MIGRATION_DIR/letsencrypt.tar.gz" -C /etc/letsencrypt .
    echo "✅ SSL certificates backed up"
else
    echo "⚠️  No SSL certificates found for $WEB_DOMAIN"
fi

# Backup secrets
echo "🔑 Backing up secrets..."
if [ -f "/opt/spameater/.env" ]; then
    cp /opt/spameater/.env "$MIGRATION_DIR/.env"
    echo "✅ Secrets backed up"
fi

# Check for Docker
echo ""
echo "🐳 Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not installed!"
    echo "   Please install Docker first:"
    echo "   https://docs.docker.com/engine/install/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not installed!"
    echo "   Please install Docker Compose first:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi
echo "✅ Docker is installed"

# Clone or update repository
echo ""
echo "📦 Setting up Docker deployment..."
DOCKER_DIR="/opt/spameater-docker"

if [ -d "$DOCKER_DIR" ]; then
    echo "Updating existing Docker setup..."
    cd "$DOCKER_DIR"
    git pull
else
    echo "Cloning SpamEater repository..."
    git clone https://github.com/rufftruffles/spameater.git "$DOCKER_DIR"
fi

cd "$DOCKER_DIR/docker"

# Create .env file
echo ""
echo "📝 Creating Docker configuration..."
cat > .env << EOF
EMAIL_DOMAIN=$EMAIL_DOMAIN
WEB_DOMAIN=$WEB_DOMAIN
DELETE_TOKEN_SECRET=$DELETE_TOKEN_SECRET
CSRF_SECRET=$CSRF_SECRET
ENCRYPTION_KEY=$ENCRYPTION_KEY
EOF

echo "✅ Configuration created"

# Create data directories
mkdir -p data logs

# Build Docker image
echo ""
echo "🔨 Building Docker image (this may take a few minutes)..."
docker compose build

# Restore data
echo ""
echo "📥 Restoring data to Docker volumes..."

# Create volumes if they don't exist
docker volume create spameater_data
docker volume create letsencrypt_certs

# Restore database and inbox files
if [ -d "$MIGRATION_DIR/data" ]; then
    echo "Restoring email data..."
    docker run --rm -v "$MIGRATION_DIR/data:/source:ro" -v spameater_data:/target alpine \
        sh -c "cp -a /source/. /target/ && chown -R 1001:1001 /target"
    echo "✅ Email data restored"
fi

# Restore certificates
if [ -f "$MIGRATION_DIR/letsencrypt.tar.gz" ]; then
    echo "Restoring SSL certificates..."
    docker run --rm -v "$MIGRATION_DIR:/source:ro" -v letsencrypt_certs:/target alpine \
        sh -c "cd /target && tar xzf /source/letsencrypt.tar.gz"
    echo "✅ SSL certificates restored"
fi

# Start Docker services
echo ""
echo "🚀 Starting Docker services..."
docker compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check health
echo ""
echo "🏥 Checking service health..."
if docker compose ps | grep -q "Up"; then
    echo "✅ Services are running"
else
    echo "⚠️  Some services may not be running properly"
    echo "   Check logs with: docker compose logs"
fi

# Disable native services
echo ""
echo "🔧 Disabling native services..."
systemctl disable haraka 2>/dev/null || true
systemctl disable spameater-api 2>/dev/null || true

# Summary
echo ""
echo "✅ Migration Complete!"
echo "===================="
echo ""
echo "📊 Migration Summary:"
echo "   Email Domain: $EMAIL_DOMAIN"
echo "   Web Domain: https://$WEB_DOMAIN"
echo "   Docker Location: $DOCKER_DIR"
echo "   Backup Location: $MIGRATION_DIR"
echo ""
echo "📝 Next Steps:"
echo "   1. Verify the service is working: https://$WEB_DOMAIN"
echo "   2. Check logs: cd $DOCKER_DIR/docker && docker compose logs"
echo "   3. Remove old installation (after verification): /opt/spameater"
echo ""
echo "⚠️  IMPORTANT:"
echo "   - The native installation has been stopped but NOT removed"
echo "   - Your data has been migrated to Docker volumes"
echo "   - Backup is saved at: $MIGRATION_DIR"
echo "   - Keep this backup until you verify everything works!"
echo ""
echo "🆘 If you need to rollback:"
echo "   1. cd $DOCKER_DIR/docker && docker compose down"
echo "   2. systemctl start haraka spameater-api"
echo "   3. systemctl enable haraka spameater-api"
