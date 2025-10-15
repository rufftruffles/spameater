# SpamEater - Self-Hosted Temporary Email Service

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](docker/)
[![Security](https://img.shields.io/badge/Security-Hardened-green.svg)](deploy/)

SpamEater is a production-ready, self-hosted temporary email service that automatically destroys emails after 24 hours. Perfect for testing, avoiding spam, and protecting your privacy.

## Features

### Core Functionality
- **Catch-all email receiver** - Accepts emails to any address @yourdomain.com
- **Auto-deletion** - All emails automatically deleted after 24 hours
- **Military-grade encryption** - AES-256-GCM encryption for email bodies
- **Web interface** - Clean, responsive UI for viewing emails
- **Real-time updates** - Instant email delivery and display
- **Mobile-friendly** - Fully responsive design

### Security Features
- **ModSecurity WAF** with OWASP Core Rule Set
- **SSL/TLS** with automatic Let's Encrypt certificates
- **Rate limiting** at nginx and application levels
- **CSRF protection** on all endpoints
- **Delete token authentication** for email removal
- **fail2ban integration** for brute force protection
- **Security event logging** and audit trails
- **XSS, SQL injection, and path traversal protection**

## Quick Start

### Step 1: Configure DNS (REQUIRED FIRST)

Before any installation, configure your DNS records:
```
MX    example.com         10 mail.example.com
A     mail.example.com    YOUR_SERVER_IP
A     example.com         YOUR_SERVER_IP
```

Verify DNS is working:
```bash
dig MX example.com
dig A mail.example.com
```

### Step 2: Choose Installation Method

#### Option A: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/rufftruffles/spameater.git
cd spameater/docker

# Configure
cp .env.example .env
# Edit .env with your domain

# Deploy
docker compose up -d
```

#### Option B: Native Installation

```bash
# Clone the repository
git clone https://github.com/rufftruffles/spameater.git
cd spameater

# Run setup (AlmaLinux/RHEL/Rocky 9)
sudo ./setup.sh
```

## Requirements

### Prerequisites (MUST be completed before installation)

1. **Domain Name**: You must own a domain (e.g., example.com)
2. **DNS Configuration**: Configure these DNS records BEFORE installation:
   ```
   MX    example.com         10 mail.example.com
   A     mail.example.com    YOUR_SERVER_IP
   A     example.com         YOUR_SERVER_IP
   ```
   **Note**: DNS changes can take up to 48 hours to propagate. Verify DNS is working before proceeding.

3. **Server Requirements**:
   - Ports 25, 80, 443 must be open and not in use
   - Root/sudo access
   - Static IP address

### For Docker
- Docker Engine 20.10+
- Docker Compose v2+
- AlmaLinux 9 / Ubuntu 22.04+ / Debian 11+ host OS

### For Native Installation
- AlmaLinux 9 / RHEL 9 / Rocky Linux 9
- Fresh installation recommended

## Configuration

### DNS Setup (Must be completed BEFORE installation)

Configure your DNS records at your domain registrar or DNS provider:
```
MX    example.com         10 mail.example.com
A     mail.example.com    YOUR_SERVER_IP
A     example.com         YOUR_SERVER_IP
```

**Important**: 
- Replace `example.com` with your actual domain
- Replace `YOUR_SERVER_IP` with your server's public IP address
- DNS changes can take up to 48 hours to propagate
- SSL certificate generation will fail if DNS is not properly configured

Verify DNS before installation:
```bash
# Test MX record
dig MX yourdomain.com

# Test A records
dig A mail.yourdomain.com
dig A yourdomain.com
```

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_DOMAIN` | Domain for receiving emails | Required |
| `WEB_DOMAIN` | Domain for web interface | EMAIL_DOMAIN |
| `DELETE_TOKEN_SECRET` | 32-char secret for delete tokens | Auto-generated |
| `CSRF_SECRET` | 32-char CSRF protection secret | Auto-generated |
| `ENCRYPTION_KEY` | 32-char encryption key | Auto-generated |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Internet  │────▶│    Nginx    │────▶│   Express   │
└─────────────┘     │  (SSL/WAF)  │     │     API     │
       │            └─────────────┘     └─────────────┘
       │                                        │
       ▼                                        ▼
┌─────────────┐                        ┌─────────────┐
│   Haraka    │───────────────────────▶│   SQLite    │
│    SMTP     │                        │   Database  │
└─────────────┘                        └─────────────┘
```

### Components
- **Haraka** - High-performance SMTP server
- **Nginx** - Web server with ModSecurity WAF
- **Express** - REST API backend
- **SQLite** - Lightweight database with encryption
- **Vanilla JS** - Frontend (no frameworks, maximum performance)

## Docker Deployment

Full Docker documentation: [docker/README.md](docker/README.md)

### Build from Source
```bash
cd docker
docker compose build --no-cache
docker compose up -d
```

## Native Installation

### Automated Setup
```bash
sudo ./setup.sh
```
The setup script will:
1. Install all dependencies
2. Configure Haraka SMTP server
3. Setup nginx with SSL
4. Configure ModSecurity WAF
5. Initialize the database
6. Setup systemd services

### Manual Uninstall
```bash
sudo ./uninstall.sh
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/inbox/create` | POST | Create temporary inbox |
| `/api/inbox/{prefix}` | GET | Get inbox contents |
| `/api/email/{id}` | GET | Get email details |
| `/api/email/{id}` | DELETE | Delete email |
| `/api/health` | GET | Health check |
| `/api/stats` | GET | Usage statistics |

## Security

SpamEater implements defense-in-depth security:

### Application Security
- Input validation and sanitization
- Parameterized queries (SQL injection prevention)
- CSRF tokens on all state-changing operations
- Rate limiting per IP and per inbox
- Secure random token generation
- Email body encryption at rest

### Infrastructure Security
- ModSecurity WAF with OWASP CRS
- fail2ban for brute force protection
- Security headers (CSP, HSTS, X-Frame-Options)
- TLS 1.2+ only
- Automatic SSL certificate renewal
- Audit logging

### Privacy
- No tracking or analytics
- No external dependencies in frontend
- All emails auto-deleted after 24 hours
- No email content logging
- No user registration required

## Testing

### Test SMTP
```bash
telnet your-server.com 25
HELO test
MAIL FROM: <test@example.org>
RCPT TO: <anything@yourdomain.com>
DATA
Subject: Test
Test message
.
QUIT
```

### Test ModSecurity
```bash
# Should return 403 Forbidden
curl "https://yourdomain.com/?test=<script>alert(1)</script>"
curl "https://yourdomain.com/../../etc/passwd"
```

## Monitoring

### View Logs
```bash
# Docker
docker compose logs -f

# Native
journalctl -u haraka -f
journalctl -u spameater-api -f
tail -f /opt/spameater/logs/modsec_audit.log
```

### Check Status
```bash
# Docker
docker compose exec spameater supervisorctl status

# Native
systemctl status haraka
systemctl status spameater-api
systemctl status nginx
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

### Development Setup
```bash
# Clone repository
git clone https://github.com/rufftruffles/spameater.git
cd spameater

# Install dependencies
npm install

# Run in development mode
NODE_ENV=development node api-server.js
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Haraka](https://haraka.github.io/) - The excellent SMTP server
- [OWASP CRS](https://coreruleset.org/) - Web application firewall rules
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL certificates

## Disclaimer

SpamEater is designed for temporary email reception. Do not use it for important emails. All emails are automatically deleted after 24 hours with no recovery option.

## Support

- **Issues**: [GitHub Issues](https://github.com/rufftruffles/spameater/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rufftruffles/spameater/discussions)
- **Security**: Report security issues via GitHub Security tab

---

**Remember**: SpamEater deletes all emails after 24 hours. No exceptions, no recovery.
