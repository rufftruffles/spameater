<div align="center">
  <h1>🍽️</h1>
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=40&pause=1000&color=FF6B35&center=true&vCenter=true&width=435&lines=SpamEater" alt="SpamEater" />
  <p><strong>Temporary Email Service with Auto-Deletion</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Security-ModSecurity%20WAF-ff6b35?style=for-the-badge&labelColor=0a0a0a" alt="Security">
    <img src="https://img.shields.io/badge/Privacy-Auto%20Delete-f7931e?style=for-the-badge&labelColor=0a0a0a" alt="Privacy">
    <img src="https://img.shields.io/badge/Node.js-22%20LTS-0a0a0a?style=for-the-badge&labelColor=ff6b35" alt="Node.js">
  </p>
</div>

---

A secure, self-hosted temporary email service that automatically deletes emails after 24 hours. Built with Node.js, Haraka SMTP server, and vanilla JavaScript.

## Features

- **Enterprise-Grade Security**: ModSecurity WAF with OWASP Core Rule Set
- **Full SMTP Server**: Receive real emails with Haraka
- **One-Command Setup**: Automated installation script
- **Modern Dark UI**: Responsive design with real-time updates
- **Auto-Deletion**: All emails permanently deleted after 24 hours
- **Lightweight**: Vanilla JS frontend, no frameworks needed
- **No User Accounts**: Complete anonymity, no registration required

## Prerequisites

Before installation, you need:

1. **A Linux server** with root access
2. **A domain name** (e.g., `example.com`)
3. **DNS records configured** (REQUIRED before running setup!)

### Required DNS Configuration

**IMPORTANT**: Configure these DNS records BEFORE running the installation script. SSL certificate generation will fail without proper DNS.

#### Option A: Subdomain for Web Interface (Recommended)
```
Type    Name                Value
------  ------------------  ------------------------
MX      example.com         10 mail.example.com
A       mail.example.com    YOUR_SERVER_IP
A       app.example.com     YOUR_SERVER_IP
```
- Emails: `user@example.com`
- Web Interface: `https://app.example.com`

#### Option B: Main Domain for Everything
```
Type    Name                Value
------  ------------------  ------------------------
MX      example.com         10 mail.example.com
A       mail.example.com    YOUR_SERVER_IP
A       example.com         YOUR_SERVER_IP
```
- Emails: `user@example.com`
- Web Interface: `https://example.com`

Wait 5-10 minutes after setting DNS for propagation before running the setup script.

## Installation

### Step 1: Configure DNS (Required First!)

1. Log into your domain registrar or DNS provider
2. Add the DNS records shown above
3. Replace `YOUR_SERVER_IP` with your actual server IP
4. Wait for DNS propagation (usually 5-10 minutes)
5. Verify DNS is working:
   ```bash
   # Test DNS resolution
   dig app.example.com
   dig mail.example.com
   ```

### Step 2: Install SpamEater

```bash
# Clone the repository
git clone https://github.com/rufftruffles/spameater.git
cd spameater

# Run the automated setup
sudo ./setup.sh
```

During setup, you'll be asked:
- **Email domain**: `example.com` (where you receive emails)
- **Web domain**: Choose either:
  - `app.example.com` (subdomain - recommended)
  - `example.com` (main domain)

The setup script will:
- Install all dependencies
- Configure Haraka SMTP server
- Set up ModSecurity WAF
- **Generate SSL certificates** (requires DNS to be configured!)
- Configure automatic cleanup
- Set up firewall rules

## Usage

After successful installation:

- **Web Interface**: `https://app.example.com`
- **Email Address**: `anything@example.com`
- **Auto-Deletion**: 24 hours

### How It Works

1. Visit `https://app.example.com`
2. Create any email address (e.g., `shopping@example.com`)
3. Use it anywhere you need a temporary email
4. Emails appear instantly in the web interface
5. All emails auto-delete after 24 hours

## Security Features

### Active Protection
- **ModSecurity WAF** with OWASP Core Rule Set (824 rules)
- **Rate Limiting** on all endpoints
- **CSRF Protection** on state-changing operations
- **SQL Injection Protection**
- **XSS Protection** 
- **Path Traversal Protection**
- **Command Injection Protection**
- **Bot/Scanner Detection**

### Privacy by Design
- **Automatic Deletion**: All emails deleted after 24 hours
- **No User Tracking**: No analytics, cookies, or logs
- **No Accounts**: No registration or personal data
- **Ephemeral Storage**: Everything is temporary
- **Database Encryption**: Email bodies encrypted at rest

## System Requirements

- **OS**: Ubuntu 20.04+, Debian 11+, RHEL 8+, AlmaLinux 8+
- **RAM**: 1GB minimum
- **Disk**: 10GB minimum
- **Ports**: 25 (SMTP), 80 (HTTP), 443 (HTTPS)
- **DNS**: Properly configured before installation

## Maintenance

### Service Management
```bash
# Check status
systemctl status haraka
systemctl status spameater-api
systemctl status nginx

# View logs
journalctl -u haraka -f
journalctl -u spameater-api -f
```

### Uninstall
```bash
# Complete removal
sudo ./uninstall.sh
```

## Configuration

### Environment Variables
Location: `/opt/spameater/.env`
```bash
DELETE_TOKEN_SECRET=  # 32-char secret
CSRF_SECRET=          # 32-char secret
ENCRYPTION_KEY=       # 32-char key
NODE_ENV=production
```

### Customization
- **Email retention**: Edit `cleanup.sh`
- **Rate limits**: Edit `nginx.conf`
- **WAF rules**: Edit `modsecurity-rules.conf`

## Important Notes

### This Service Is Temporary
- Emails are **permanently deleted** after 24 hours
- **No recovery** possible after deletion
- **Not for important emails**
- Anyone can use any email prefix

### Good For
- Avoiding spam on signups
- Testing email functionality
- One-time verifications
- Protecting your real email
- Anonymous registrations

### Not Good For
- Important communications
- Password resets you'll need later
- Financial transactions
- Business email
- Long-term storage

## Troubleshooting

### SSL Certificate Failed
- Ensure DNS is properly configured
- Wait for DNS propagation
- Check domain points to correct IP
- Verify ports 80/443 are open

### Emails Not Receiving
- Check port 25 is open
- Verify MX records
- Check `systemctl status haraka`
- Review `/var/log/mail.log`

### Web Interface Not Loading
- Check nginx: `systemctl status nginx`
- Verify SSL certificate: `certbot certificates`
- Check firewall rules

## Contributing

1. Fork the repository
2. Create your feature branch
3. Test your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file

## Support

- **Issues**: [GitHub Issues](https://github.com/rufftruffles/spameater/issues)
- **Wiki**: [Documentation](https://github.com/rufftruffles/spameater/wiki)
- **Security**: Report vulnerabilities via GitHub Security

---

<div align="center">
  <strong>Remember: All emails auto-delete after 24 hours. No exceptions.</strong>
  <br><br>
  <img src="https://img.shields.io/badge/Made%20with-🧡-ff6b35?style=flat-square" alt="Made with love">
</div>
