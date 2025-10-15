FROM almalinux:9

# Set environment variables for non-interactive installation
ENV NODE_ENV=production
ENV HARAKA_HOME=/opt/spameater/haraka
ENV NPM_CONFIG_PREFIX=/usr/local
ENV PATH=$NPM_CONFIG_PREFIX/bin:$PATH

# Create spameater user early (same as production)
RUN useradd -r -s /bin/false -d /opt/spameater spameater

# Update system and install EPEL
RUN dnf update -y -q && \
    dnf install -y epel-release && \
    dnf config-manager --set-enabled epel && \
    # Enable CRB (CodeReady Builder) - this is what provides ModSecurity packages
    /usr/bin/crb enable || dnf config-manager --set-enabled crb || \
    dnf config-manager --set-enabled powertools || \
    echo "CRB/PowerTools repo might not be available"

# Fix curl conflict in AlmaLinux 9 minimal image
RUN dnf swap -y curl-minimal curl || dnf install -y curl --allowerasing

# Install base dependencies INCLUDING ModSecurity from CRB/EPEL
RUN dnf install -y \
    wget git which procps-ng make gcc gcc-c++ \
    python3 python3-devel python3-pip \
    sqlite sqlite-devel \
    nginx certbot python3-certbot-nginx \
    fail2ban supervisor cronie firewalld && \
    dnf groupinstall -y "Development Tools" && \
    # This should work with CRB enabled - same as your original setup
    dnf install -y nginx-mod-modsecurity libmodsecurity mod_security_crs || \
    dnf install -y nginx-module-modsecurity || \
    echo "ModSecurity packages not found in repos"

# Install Node.js 22 LTS
RUN curl -fsSL https://rpm.nodesource.com/setup_22.x | bash - && \
    dnf install -y nodejs && \
    node --version && \
    npm --version

# Update npm and install global tools
RUN npm install -g npm@latest && \
    npm install -g node-gyp

# Try to install ModSecurity (may not be available)
RUN dnf install -y nginx-mod-modsecurity libmodsecurity mod_security_crs || \
    echo "ModSecurity packages not available in base repos"

# Clean up
RUN dnf clean all && \
    rm -rf /var/cache/dnf

# Verify Node.js version
RUN node_version=$(node --version | sed 's/v//' | cut -d. -f1) && \
    if [ "$node_version" -lt 22 ]; then \
        echo "ERROR: Node.js version too old"; \
        exit 1; \
    fi

# Create directory structure
RUN mkdir -p /opt/spameater/{haraka,frontend,data,logs,modsecurity} \
             /opt/spameater/data/inboxes \
             /opt/spameater/haraka/{queue,plugins,config} \
             /opt/spameater/frontend/.well-known \
             /var/www/html/.well-known/acme-challenge && \
    chown -R spameater:spameater /opt/spameater && \
    chmod 755 /opt/spameater /opt/spameater/data

# Copy all project files
COPY --chown=root:root . /tmp/spameater-build/

# Copy Docker-specific files
COPY docker/supervisord.conf /etc/supervisord.conf
COPY docker/docker-setup.sh /usr/local/bin/docker-setup.sh
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/nginx-docker.conf /etc/nginx/conf.d/spameater.conf.template

# Make scripts executable
RUN chmod +x /usr/local/bin/docker-setup.sh /usr/local/bin/entrypoint.sh

# Verify scripts are executable and complete
RUN ls -la /usr/local/bin/docker-setup.sh && \
    head -n 5 /usr/local/bin/docker-setup.sh && \
    tail -n 5 /usr/local/bin/docker-setup.sh

# Run build-time setup
RUN /usr/local/bin/docker-setup.sh

# Set ownership after setup
RUN chown -R spameater:spameater /opt/spameater && \
    chmod 600 /opt/spameater/data/emails.db 2>/dev/null || true

# Create volume mount points
VOLUME ["/opt/spameater/data", "/opt/spameater/logs", "/etc/letsencrypt"]

# Expose ports
EXPOSE 25 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost/api/health || exit 1

# Run entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
