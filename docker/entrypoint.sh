#!/bin/bash
# SpamEater Docker Runtime Entrypoint
# Handles environment configuration and service startup

set -e

echo "🍽️ SpamEater Starting..."
echo "======================="

# Validate required environment variables
if [ -z "$EMAIL_DOMAIN" ]; then
    echo "❌ ERROR: EMAIL_DOMAIN environment variable is required!"
    echo "   Example: docker run -e EMAIL_DOMAIN=example.com ..."
    exit 1
fi

# Set defaults
WEB_DOMAIN="${WEB_DOMAIN:-$EMAIL_DOMAIN}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@$EMAIL_DOMAIN}"

# Secrets live on the data volume so container recreation reuses them.
# Losing ENCRYPTION_KEY makes every stored email permanently unreadable.
# Order: explicit environment variables win, then the volume file, then
# generation (first start only).
PERSISTED_ENV=/opt/spameater/data/.env
LEGACY_ENV=/opt/spameater/.env

mkdir -p /opt/spameater/data

# Restart-in-place migration from pre-v4 containers that only had the
# non-volume file. On a recreate the legacy file is already gone.
if [ -z "$ENCRYPTION_KEY" ] && [ ! -f "$PERSISTED_ENV" ] && [ -f "$LEGACY_ENV" ]; then
    cp "$LEGACY_ENV" "$PERSISTED_ENV"
    echo "🔐 Migrated existing secrets to the data volume"
fi

# Parse, never source: the file lives on a writable volume and this
# entrypoint runs as root, so executing it as shell code is off the table.
# Explicitly-set environment variables win over persisted values.
read_persisted() {
    grep "^$1=" "$PERSISTED_ENV" 2>/dev/null | head -1 | cut -d= -f2-
}
if [ -f "$PERSISTED_ENV" ]; then
    if [ -z "$DELETE_TOKEN_SECRET" ]; then DELETE_TOKEN_SECRET=$(read_persisted DELETE_TOKEN_SECRET); fi
    if [ -z "$CSRF_SECRET" ]; then CSRF_SECRET=$(read_persisted CSRF_SECRET); fi
    if [ -z "$ENCRYPTION_KEY" ]; then ENCRYPTION_KEY=$(read_persisted ENCRYPTION_KEY); fi
    echo "🔐 Loaded secrets from the data volume"
fi

# openssl rand -hex 16 always yields exactly 32 chars of full entropy
# (the old base64|tr|cut pipeline could come up short after stripping)
if [ -z "$DELETE_TOKEN_SECRET" ]; then
    DELETE_TOKEN_SECRET=$(openssl rand -hex 16)
    echo "🔐 Generated DELETE_TOKEN_SECRET"
fi

if [ -z "$CSRF_SECRET" ]; then
    CSRF_SECRET=$(openssl rand -hex 16)
    echo "🔐 Generated CSRF_SECRET"
fi

if [ -z "$ENCRYPTION_KEY" ]; then
    ENCRYPTION_KEY=$(openssl rand -hex 16)
    echo "🔐 Generated ENCRYPTION_KEY"
fi

# Persist to the volume (root-owned: only this entrypoint reads it),
# mirror to the app-visible path
cat > "$PERSISTED_ENV" << EOF
DELETE_TOKEN_SECRET=$DELETE_TOKEN_SECRET
CSRF_SECRET=$CSRF_SECRET
ENCRYPTION_KEY=$ENCRYPTION_KEY
EOF
chown root:root "$PERSISTED_ENV"
chmod 600 "$PERSISTED_ENV"

cat > "$LEGACY_ENV" << EOF
DELETE_TOKEN_SECRET=$DELETE_TOKEN_SECRET
CSRF_SECRET=$CSRF_SECRET
ENCRYPTION_KEY=$ENCRYPTION_KEY
NODE_ENV=production
EOF
chown spameater:spameater "$LEGACY_ENV"
chmod 600 "$LEGACY_ENV"

echo "✅ Environment configured"

# Process Haraka config templates
echo "📧 Configuring Haraka for domain: $EMAIL_DOMAIN"
sed "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" /opt/spameater/haraka/config/me.template > /opt/spameater/haraka/config/me
sed "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" /opt/spameater/haraka/config/host_list.template > /opt/spameater/haraka/config/host_list
chown spameater:spameater /opt/spameater/haraka/config/{me,host_list}

# Process nginx config template
echo "🌐 Configuring nginx for web domain: $WEB_DOMAIN"
if [ -f "/etc/nginx/conf.d/spameater.conf.template" ]; then
    cp /etc/nginx/conf.d/spameater.conf.template /etc/nginx/conf.d/spameater.conf
else
    # Use the default nginx config from deploy
    if [ -f "/tmp/spameater-build/deploy/nginx.conf" ]; then
        cp /tmp/spameater-build/deploy/nginx.conf /etc/nginx/conf.d/spameater.conf
    fi
fi

# Replace placeholders in nginx config
sed -i "s/DOMAIN_PLACEHOLDER/$WEB_DOMAIN/g" /etc/nginx/conf.d/spameater.conf
sed -i "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" /etc/nginx/conf.d/spameater.conf

# Process frontend template
sed -i "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" /opt/spameater/frontend/index.html

# Process security.txt template if exists
if [ -f "/opt/spameater/frontend/.well-known/security.txt.template" ]; then
    EXPIRY_DATE=$(date -d "+1 year" -u +"%Y-%m-%dT%H:%M:%S.000Z")
    sed -e "s/EMAIL_DOMAIN_PLACEHOLDER/$EMAIL_DOMAIN/g" \
        -e "s/EXPIRY_DATE_PLACEHOLDER/$EXPIRY_DATE/g" \
        /opt/spameater/frontend/.well-known/security.txt.template > /opt/spameater/frontend/.well-known/security.txt
    rm -f /opt/spameater/frontend/.well-known/security.txt.template
fi

# Check if ModSecurity is available and configure it
echo "🛡️ Configuring ModSecurity WAF..."

# Check for ModSecurity module in multiple possible locations
MODSEC_MODULE=""
if [ -f "/usr/share/nginx/modules/ngx_http_modsecurity_module.so" ]; then
    MODSEC_MODULE="/usr/share/nginx/modules/ngx_http_modsecurity_module.so"
elif [ -f "/etc/nginx/modules/ngx_http_modsecurity_module.so" ]; then
    MODSEC_MODULE="/etc/nginx/modules/ngx_http_modsecurity_module.so"
elif [ -f "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so" ]; then
    MODSEC_MODULE="/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so"
fi

if [ -n "$MODSEC_MODULE" ] && [ -d "/opt/spameater/modsecurity/crs" ]; then
    echo "Found ModSecurity module at: $MODSEC_MODULE"
    
    # Check if module is already being loaded anywhere
    if ! grep -r "load_module.*modsecurity" /etc/nginx/ /usr/share/nginx/ 2>/dev/null | grep -v ":#"; then
        # Only add if not already loaded
        echo "Adding ModSecurity module to nginx.conf..."
        sed -i "1i load_module $MODSEC_MODULE;" /etc/nginx/nginx.conf
    else
        echo "ModSecurity module already loaded in nginx configuration"
    fi
    
    # Add ModSecurity rules to server block in nginx config if not present
    if ! grep -q "modsecurity" /etc/nginx/conf.d/spameater.conf; then
        # Create a main rules file that includes everything
        cat > /opt/spameater/modsecurity/main.conf << 'EOF'
# Main ModSecurity configuration
Include /opt/spameater/modsecurity/modsecurity.conf
Include /opt/spameater/modsecurity/spameater-rules.conf

# OWASP CRS
Include /opt/spameater/modsecurity/crs/crs-setup.conf
Include /opt/spameater/modsecurity/crs/rules/*.conf
EOF
        
        # Add to nginx config - just point to the main file
        sed -i '/server_tokens off;/a\    \n    # ModSecurity WAF\n    modsecurity on;\n    modsecurity_rules_file /opt/spameater/modsecurity/main.conf;' /etc/nginx/conf.d/spameater.conf
    fi
    
    echo "✅ ModSecurity WAF enabled with SpamEater rules and OWASP CRS"
else
    echo "⚠️ ModSecurity module not found or configuration missing"
    if [ -z "$MODSEC_MODULE" ]; then
        echo "   Module not found in expected locations"
    fi
    if [ ! -d "/opt/spameater/modsecurity/crs" ]; then
        echo "   OWASP CRS not installed"
    fi
fi

# SSL Certificate Handling
echo "🔒 Configuring SSL certificates..."

# Check if running in development mode (no SSL)
if [ "$DISABLE_SSL" = "true" ]; then
    echo "⚠️ SSL disabled (development mode)"
    # Remove SSL sections from nginx config
    sed -i '/listen 443/,/^}/d' /etc/nginx/conf.d/spameater.conf
else
    # Production mode - handle SSL certificates
    if [ -d "/etc/letsencrypt/live/$WEB_DOMAIN" ]; then
        echo "✅ SSL certificates found for $WEB_DOMAIN"

        # Check certificate validity
        if openssl x509 -checkend 86400 -noout -in "/etc/letsencrypt/live/$WEB_DOMAIN/cert.pem" 2>/dev/null; then
            echo "✅ Certificate is valid"
        else
            echo "⚠️ Certificate expiring soon, attempting renewal..."
            certbot renew --quiet || echo "⚠️ Renewal failed, will retry later"
        fi

        # Configure nginx to use existing certificates
        echo "🔧 Configuring nginx for SSL..."
        certbot --nginx \
            -d "$WEB_DOMAIN" \
            --redirect \
            --non-interactive \
            --reinstall || echo "⚠️ Could not configure nginx for SSL, may need manual setup"

        # Stop nginx so supervisord can start it fresh
        nginx -s stop 2>/dev/null || pkill nginx 2>/dev/null || true
        sleep 1
    else
        echo "📋 No existing SSL certificates found"
        
        # Only attempt certificate generation if we can reach Let's Encrypt
        if [ "$AUTO_SSL" != "false" ]; then
            echo "🔐 Attempting to generate SSL certificates..."
            echo "   This requires ports 80/443 to be accessible from the internet"
            echo "   and DNS records pointing to this server."
            
            # Start nginx temporarily for ACME challenge
            nginx
            sleep 2
            
            # Attempt to get certificates
            if certbot certonly --nginx \
                -d "$WEB_DOMAIN" \
                --email "$ADMIN_EMAIL" \
                --agree-tos \
                --non-interactive \
                --keep-until-expiring; then
                echo "✅ SSL certificates generated successfully"
                
                # Configure nginx for SSL
                certbot --nginx \
                    -d "$WEB_DOMAIN" \
                    --redirect \
                    --non-interactive \
                    --reinstall
            else
                echo "⚠️ SSL certificate generation failed"
                echo "   The service will run on HTTP only"
                echo "   You can manually run certbot later"
            fi
            
            # Stop temporary nginx
            nginx -s stop 2>/dev/null || true
            sleep 2
        else
            echo "⚠️ AUTO_SSL disabled, skipping certificate generation"
        fi
    fi
fi

# Test nginx configuration
echo "🔍 Testing nginx configuration..."
if nginx -t 2>/dev/null; then
    echo "✅ Nginx configuration valid"
else
    echo "❌ Nginx configuration error"
    nginx -T
    exit 1
fi

# Ensure proper permissions
chown -R spameater:spameater /opt/spameater/data /opt/spameater/logs
chmod 755 /opt/spameater/data
chmod 600 /opt/spameater/data/emails.db 2>/dev/null || true

# Setup cron for certificate renewal
if [ "$DISABLE_SSL" != "true" ] && [ -d "/etc/letsencrypt/live/$WEB_DOMAIN" ]; then
    echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'nginx -s reload'" > /etc/cron.d/certbot-renew
    chmod 644 /etc/cron.d/certbot-renew
fi

# Display configuration summary
echo ""
echo "✅ SpamEater Configuration Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📧 Email Domain: $EMAIL_DOMAIN"
if [ "$DISABLE_SSL" = "true" ]; then
    echo "🌐 Web Access: http://$WEB_DOMAIN"
else
    echo "🌐 Web Access: https://$WEB_DOMAIN"
fi
echo "📊 Admin Email: $ADMIN_EMAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start supervisord to manage all services
echo "🚀 Starting services..."

# Export environment variables for child processes
export DELETE_TOKEN_SECRET
export CSRF_SECRET
export ENCRYPTION_KEY
export NODE_ENV=production

# Secrets stay owner-readable only; services get them via exported env
chown spameater:spameater /opt/spameater/.env
chmod 600 /opt/spameater/.env

exec supervisord -c /etc/supervisord.conf
