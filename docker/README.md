# SpamEater Docker Deployment

Deploy SpamEater with all security features intact using Docker. This containerized version maintains 100% feature parity with the production AlmaLinux 9 setup.

## Quick Start

### Important: DNS Setup Required First

**You MUST configure DNS before running Docker installation.** The SSL certificate generation will fail without proper DNS.

### Prerequisites

1. **Domain ownership** - You must own a domain (e.g., `example.com`)

2. **DNS Configuration (REQUIRED FIRST)** - Configure these records before proceeding:
   ```
   MX    example.com         10 mail.example.com
   A     mail.example.com    YOUR_SERVER_IP
   A     example.com         YOUR_SERVER_IP  (or app.example.com for subdomain)
   ```

3. **Verify DNS is working**:
   ```bash
   # Check MX record
   dig MX example.com
   # Should show: example.com. 3600 IN MX 10 mail.example.com.
   
   # Check A record
   dig A mail.example.com
   # Should show your server's IP address
   ```

4. **Server requirements**:
   - Docker Engine 20.10+ and Docker Compose v2+
   - Ports 25, 80, and 443 open and not in use
   - Static IP address

### Deploy

Only after DNS is verified working:

```bash
# Clone the repository
git clone https://github.com/rufftruffles/spameater.git
cd spameater/docker

# Configure environment
cp .env.example .env
nano .env  # Edit EMAIL_DOMAIN with your actual domain

# Deploy
docker compose up -d

# Check logs
docker compose logs -f
```

### Access

- Web Interface: `https://your-domain.com` (or subdomain)
- Email: `anything@your-domain.com`

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EMAIL_DOMAIN` | Yes | - | Domain for receiving emails (e.g., `example.com`) |
| `WEB_DOMAIN` | No | `EMAIL_DOMAIN` | Domain for web access (e.g., `mail.example.com`) |
| `ADMIN_EMAIL` | No | `admin@EMAIL_DOMAIN` | Email for Let's Encrypt notifications |
| `DELETE_TOKEN_SECRET` | No | Auto-generated | 32-character secret for delete tokens |
| `CSRF_SECRET` | No | Auto-generated | 32-character CSRF protection secret |
| `ENCRYPTION_KEY` | No | Auto-generated | 32-character encryption key |
| `DISABLE_SSL` | No | `false` | Set to `true` for HTTP-only (development) |
| `AUTO_SSL` | No | `true` | Auto-generate SSL certificates |

### Volume Mounts

The compose file creates three persistent volumes:

- `spameater_data`: Email database and JSON files
- `spameater_logs`: Application logs
- `letsencrypt_certs`: SSL certificates

## SSL Certificates

### Important: DNS Must Be Working First

**SSL certificate generation will fail if DNS is not properly configured.** Make sure your domain points to your server's IP address before deploying.

### Automatic SSL (Production)

The container automatically obtains Let's Encrypt certificates if:
1. **DNS is properly configured and propagated** (most important)
2. Ports 80/443 are accessible from internet
3. `AUTO_SSL` is not set to `false`

If SSL generation fails during first startup, it's usually because:
- DNS is not pointing to your server yet
- DNS hasn't propagated (can take up to 48 hours)
- Ports 80/443 are blocked by firewall

### Manual SSL

If automatic SSL fails or you prefer manual setup:

```bash
# Enter the container
docker exec -it spameater bash

# Run certbot manually
certbot --nginx -d your-domain.com --email admin@your-domain.com

# Restart nginx
nginx -s reload
```

### Development Mode (No SSL)

For local development without SSL:

```bash
# In .env file
DISABLE_SSL=true
```

## Service Management

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f spameater

# Inside container
docker exec -it spameater tail -f /opt/spameater/logs/haraka.log
docker exec -it spameater tail -f /opt/spameater/logs/api.log
```

### Restart Services

```bash
# Restart all
docker compose restart

# Inside container - individual services
docker exec -it spameater supervisorctl restart haraka
docker exec -it spameater supervisorctl restart spameater-api
docker exec -it spameater supervisorctl restart nginx
```

### Service Status

```bash
# Check health
docker compose ps

# Inside container
docker exec -it spameater supervisorctl status
```

## Security Features

All security features from the production setup are preserved:

### Application Security
- CSRF token protection
- Delete token authentication
- Email body encryption (AES-256-GCM)
- Rate limiting (nginx + application)
- Path traversal protection
- SQL injection prevention
- XSS protection

### Infrastructure Security
- ModSecurity WAF with OWASP CRS (enabled via EPEL/CRB repositories)
- fail2ban protection
- Security event logging
- Automatic cleanup after 24 hours

### Container Security
- Non-root user for application processes
- Minimal base image (AlmaLinux 9)
- No unnecessary packages
- Secrets management via environment variables

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose logs spameater

# Verify environment
docker compose config

# Check port availability
netstat -tulpn | grep -E ':(25|80|443)'
```

### Emails Not Receiving

1. Check DNS:
   ```bash
   dig MX your-domain.com
   dig A mail.your-domain.com
   ```

2. Check Haraka:
   ```bash
   docker exec -it spameater supervisorctl status haraka
   docker exec -it spameater tail -f /opt/spameater/logs/haraka.log
   ```

3. Test SMTP:
   ```bash
   telnet your-server-ip 25
   ```

### SSL Issues

```bash
# Check certificate status
docker exec -it spameater certbot certificates

# Renew manually
docker exec -it spameater certbot renew

# Check nginx config
docker exec -it spameater nginx -t
```

### Database Issues

```bash
# Check database
docker exec -it spameater sqlite3 /opt/spameater/data/emails.db ".tables"

# Check permissions
docker exec -it spameater ls -la /opt/spameater/data/
```

## Updating

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker compose build --no-cache
docker compose up -d

# Check new version
docker compose logs | head -20
```

## Backup and Restore

### Backup

```bash
# Backup data volume
docker run --rm -v docker_spameater_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/spameater-backup-$(date +%Y%m%d).tar.gz -C /data .

# Backup certificates
docker run --rm -v docker_letsencrypt_certs:/certs -v $(pwd):/backup alpine \
  tar czf /backup/certs-backup-$(date +%Y%m%d).tar.gz -C /certs .
```

### Restore

```bash
# Restore data
docker run --rm -v docker_spameater_data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/spameater-backup-YYYYMMDD.tar.gz -C /data

# Restore certificates
docker run --rm -v docker_letsencrypt_certs:/certs -v $(pwd):/backup alpine \
  tar xzf /backup/certs-backup-YYYYMMDD.tar.gz -C /certs
```

## Production Deployment

### Recommended Server Specs

- **Minimum**: 1 CPU, 1GB RAM, 10GB disk
- **Recommended**: 2 CPU, 2GB RAM, 20GB disk
- **OS**: Any Linux with Docker support

### Security Hardening

1. **Use Docker secrets** for sensitive data instead of environment variables
2. **Enable firewall** on host system
3. **Regular updates**: Keep Docker and base image updated
4. **Monitor logs**: Set up log aggregation
5. **Rate limiting**: Adjust nginx rate limits based on usage

### Scaling

For high-volume deployments:

```yaml
# docker-compose.override.yml
services:
  spameater:
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '4'
          memory: 4G
```

## Differences from Native Installation

| Feature | Native | Docker | Notes |
|---------|--------|--------|-------|
| Base OS | AlmaLinux 9 | AlmaLinux 9 | Same |
| Services | systemd | supervisord | Equivalent functionality |
| Firewall | firewalld | Host firewall | Configure on host |
| SSL | certbot | certbot | Same, persisted in volume |
| ModSecurity | Yes | Yes | Enabled via EPEL/CRB repositories |
| fail2ban | Yes | Limited | Requires privileged mode |

## Support

- **Issues**: [GitHub Issues](https://github.com/rufftruffles/spameater/issues)
- **Security**: Report via GitHub Security tab

## License

MIT License - See [LICENSE](../LICENSE) file

---

**Remember**: All emails auto-delete after 24 hours. No exceptions.
