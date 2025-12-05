# Proxy Panel - Auto Installation

Simple, automated installation script for Debian/Ubuntu servers with Cloudflare domain setup.

## 🚀 Quick Start

### 1. Upload Files to Server

Upload all files to your server:
- `pvm.py`
- `requirements.txt`
- `templates/` (directory)
- `install.sh`

### 2. Run Installation Script

```bash
# Make script executable
chmod +x install.sh

# Run installation (as root)
sudo bash install.sh
```

The script will ask you for:
- Server IP address
- Domain name
- Admin password
- 3proxy port (default: 3128)
- Whether to install SSL certificate

### 3. Configure Cloudflare DNS

1. Go to https://dash.cloudflare.com
2. Select your domain
3. Go to **DNS** > **Records**
4. Add/Edit A record:
   - Type: `A`
   - Name: `@` (or blank)
   - Content: `YOUR_SERVER_IP`
   - Proxy: `Proxied` (orange cloud)
5. Go to **SSL/TLS** > Set mode to `Full` or `Full (strict)`

### 4. Access Your Panel

Open browser: `https://yourdomain.com`
Login with your admin password.

## 📋 Requirements

- Debian 11/12 or Ubuntu 20.04/22.04
- Root or sudo access
- Domain name configured in Cloudflare
- Server IP address

## 🔧 Manual Installation Steps

If you prefer manual installation, the script performs these steps:

1. Update system packages
2. Install dependencies (Python, Nginx, 3proxy, Certbot)
3. Create application user
4. Setup Python virtual environment
5. Install Python packages
6. Configure 3proxy
7. Setup firewall rules
8. Create systemd service
9. Configure Nginx reverse proxy
10. Install SSL certificate (optional)
11. Start services

## 📝 Useful Commands

```bash
# Check service status
sudo systemctl status proxy-panel

# View logs
sudo journalctl -u proxy-panel -f

# Restart service
sudo systemctl restart proxy-panel

# Install SSL certificate manually
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

## 🔐 Security Notes

- Change default admin password after first login
- Keep system updated: `sudo apt update && sudo apt upgrade`
- Enable Cloudflare proxy for DDoS protection
- Use strong passwords

## 🆘 Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u proxy-panel -n 50

# Check if files exist
ls -la /home/proxypanel/proxy-panel/
```

### Can't access domain
- Verify DNS is configured in Cloudflare
- Check firewall: `sudo ufw status`
- Test locally: `curl http://localhost:8000`

### SSL certificate error
- Ensure DNS is pointing to server
- Verify Cloudflare SSL mode is "Full"
- Try installing manually: `sudo certbot --nginx -d yourdomain.com`

## 📞 Support

Check service logs for detailed error messages:
```bash
sudo journalctl -u proxy-panel -f
```

---

**🎉 Enjoy your Proxy Panel!**

