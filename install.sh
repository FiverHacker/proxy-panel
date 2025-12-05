#!/bin/bash
# Proxy Panel - Complete Auto Installation Script for Debian/Ubuntu
# This script will install and configure everything automatically

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
clear
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║           Proxy Panel - Auto Installation Script           ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root or with sudo${NC}"
    echo -e "${YELLOW}Usage: sudo bash install.sh${NC}"
    exit 1
fi

# Function to ask for input
ask_input() {
    local prompt=$1
    local default=$2
    local var_name=$3
    
    if [ -n "$default" ]; then
        read -p "$(echo -e ${CYAN}$prompt ${NC}[$default]: )" input
        eval $var_name="${input:-$default}"
    else
        read -p "$(echo -e ${CYAN}$prompt${NC}: )" input
        eval $var_name="$input"
    fi
}

# Function to ask for password (hidden)
ask_password() {
    local prompt=$1
    local var_name=$2
    
    read -sp "$(echo -e ${CYAN}$prompt${NC}: )" password
    echo ""
    eval $var_name="$password"
}

# Collect information
echo -e "${BLUE}📋 Please provide the following information:${NC}"
echo ""

# Auto-detect server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "")

# Get domain name
ask_input "Enter your domain name (e.g., example.com)" "" "DOMAIN"

# Get admin password
ask_password "Enter admin password for proxy panel" "ADMIN_PASS"
if [ -z "$ADMIN_PASS" ]; then
    echo -e "${RED}❌ Admin password cannot be empty!${NC}"
    exit 1
fi

# Confirm password
ask_password "Confirm admin password" "ADMIN_PASS_CONFIRM"
if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
    echo -e "${RED}❌ Passwords do not match!${NC}"
    exit 1
fi

# Ask for 3proxy port
ask_input "Enter 3proxy port (default: 3128)" "3128" "PROXY_PORT"

# Ask if they want SSL certificate
echo ""
echo -e "${YELLOW}Do you want to install SSL certificate automatically? (requires domain DNS configured)${NC}"
read -p "Install SSL certificate? (y/n) [n]: " INSTALL_SSL
INSTALL_SSL=${INSTALL_SSL:-n}

echo ""
echo -e "${GREEN}✓ Information collected!${NC}"
echo ""
echo -e "${BLUE}Configuration Summary:${NC}"
echo -e "  Domain: ${CYAN}$DOMAIN${NC}"
echo -e "  Admin Password: ${CYAN}***${NC}"
echo -e "  3proxy Port: ${CYAN}$PROXY_PORT${NC}"
echo -e "  Install SSL: ${CYAN}$INSTALL_SSL${NC}"
echo -e "  Server IP: ${CYAN}Auto-detected${NC}"
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Installation steps
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Starting installation...${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Step 1: Update system
echo -e "${BLUE}[1/12] Updating system packages...${NC}"
apt update -qq && apt upgrade -y -qq
echo -e "${GREEN}✓ System updated${NC}"

# Step 2: Install dependencies
echo -e "${BLUE}[2/12] Installing dependencies...${NC}"
apt install -y python3 python3-pip python3-venv curl wget git nginx ufw certbot python3-certbot-nginx 3proxy > /dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 3: Check application files in current directory
echo -e "${BLUE}[3/10] Checking application files...${NC}"
APP_DIR=$(pwd)
CURRENT_USER=$(whoami)

if [ ! -f "pvm.py" ]; then
    echo -e "${RED}❌ Error: pvm.py not found in current directory!${NC}"
    echo -e "${YELLOW}Please run this script from the directory containing pvm.py${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Application files found in: $APP_DIR${NC}"

# Step 4: Setup Python environment
echo -e "${BLUE}[4/10] Setting up Python environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv > /dev/null 2>&1
fi
./venv/bin/pip install --upgrade pip > /dev/null 2>&1

if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt > /dev/null 2>&1
else
    ./venv/bin/pip install fastapi uvicorn jinja2 python-multipart speedtest-cli > /dev/null 2>&1
fi
echo -e "${GREEN}✓ Python packages installed${NC}"

# Step 5: Create database file
echo -e "${BLUE}[5/10] Creating database file...${NC}"
if [ ! -f "proxy_users.json" ]; then
    echo "{}" > proxy_users.json
    chmod 644 proxy_users.json
fi
echo -e "${GREEN}✓ Database file created${NC}"

# Step 6: Setup 3proxy config
echo -e "${BLUE}[6/10] Configuring 3proxy...${NC}"
if [ -d "/etc/3proxy" ] && [ ! -f /etc/3proxy/3proxy.cfg ]; then
    cat > /etc/3proxy/3proxy.cfg <<EOF
daemon
maxconn 1000
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth strong
users
allow * * * 80-88,8080-8088 HTTP
allow * * * 443,8443 HTTPS
proxy -n
flush
EOF
fi

systemctl enable 3proxy > /dev/null 2>&1
systemctl restart 3proxy > /dev/null 2>&1
echo -e "${GREEN}✓ 3proxy configured${NC}"

# Step 7: Configure firewall
echo -e "${BLUE}[7/10] Configuring firewall...${NC}"
ufw --force enable > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow 22/tcp > /dev/null 2>&1
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw allow ${PROXY_PORT}/tcp > /dev/null 2>&1
echo -e "${GREEN}✓ Firewall configured${NC}"

# Step 8: Create systemd service
echo -e "${BLUE}[8/10] Creating systemd service...${NC}"
cat > /etc/systemd/system/proxy-panel.service <<EOF
[Unit]
Description=Proxy Panel Web Interface
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
Group=${CURRENT_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
Environment="ADMIN_PASS=${ADMIN_PASS}"
Environment="THREEPROXY_CFG=/etc/3proxy/3proxy.cfg"
Environment="NET_DEV=eth0"
ExecStart=${APP_DIR}/venv/bin/python3 ${APP_DIR}/pvm.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-panel > /dev/null 2>&1
echo -e "${GREEN}✓ Systemd service created${NC}"

# Step 9: Configure Nginx
echo -e "${BLUE}[9/10] Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/proxy-panel <<EOF
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 300s;
        proxy_connect_timeout 300s;
    }
    
    client_max_body_size 10M;
}
EOF

ln -sf /etc/nginx/sites-available/proxy-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

if nginx -t > /dev/null 2>&1; then
    systemctl restart nginx > /dev/null 2>&1
    echo -e "${GREEN}✓ Nginx configured${NC}"
else
    echo -e "${RED}❌ Nginx configuration error!${NC}"
    nginx -t
fi

# Step 10: Install SSL certificate (optional)
if [ "$INSTALL_SSL" = "y" ] || [ "$INSTALL_SSL" = "Y" ]; then
    echo -e "${BLUE}[10/10] Installing SSL certificate...${NC}"
    echo -e "${YELLOW}Make sure your domain DNS is pointing to this server!${NC}"
    read -p "Press Enter to continue with SSL installation..."
    
    if certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email > /dev/null 2>&1; then
        echo -e "${GREEN}✓ SSL certificate installed${NC}"
        SSL_INSTALLED=true
    else
        echo -e "${YELLOW}⚠ SSL certificate installation failed. You can install it manually later with:${NC}"
        echo -e "${CYAN}   certbot --nginx -d ${DOMAIN} -d www.${DOMAIN}${NC}"
        SSL_INSTALLED=false
    fi
else
    echo -e "${BLUE}[10/10] Skipping SSL certificate installation...${NC}"
    SSL_INSTALLED=false
fi

# Step 13: Start service
echo -e "${BLUE}Starting proxy panel service...${NC}"
systemctl start proxy-panel
sleep 2

# Check if service is running
if systemctl is-active --quiet proxy-panel; then
    echo -e "${GREEN}✓ Proxy panel service started${NC}"
else
    echo -e "${YELLOW}⚠ Service failed to start. Check logs with: journalctl -u proxy-panel${NC}"
fi

# Final summary
clear
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║              ✅ Installation Complete! ✅                  ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

echo -e "${CYAN}📋 Installation Summary:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Domain:           ${GREEN}$DOMAIN${NC}"
echo -e "  3proxy Port:      ${GREEN}$PROXY_PORT${NC}"
echo -e "  SSL Installed:    ${GREEN}$SSL_INSTALLED${NC}"
echo -e "  Server IP:        ${GREEN}Auto-detected${NC}"
echo ""

echo -e "${CYAN}🔧 Next Steps:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Cloudflare instructions
echo -e "${YELLOW}1. Configure Cloudflare DNS:${NC}"
echo -e "   • Go to: ${BLUE}https://dash.cloudflare.com${NC}"
echo -e "   • Select your domain: ${GREEN}$DOMAIN${NC}"
echo -e "   • Go to DNS > Records"
    echo -e "   • Add/Edit A record:"
    echo -e "     - Type: A"
    echo -e "     - Name: @ (or leave blank)"
    echo -e "     - Content: ${GREEN}Your Server IP${NC} (check your VPS provider)"
    echo -e "     - Proxy: ${GREEN}Proxied${NC} (orange cloud)"
echo -e "   • Go to SSL/TLS > Set mode to: ${GREEN}Full${NC} or ${GREEN}Full (strict)${NC}"
echo ""

# SSL instructions if not installed
if [ "$SSL_INSTALLED" = false ]; then
    echo -e "${YELLOW}2. Install SSL Certificate (after DNS is configured):${NC}"
    echo -e "   ${CYAN}sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN${NC}"
    echo ""
fi


# Access information
echo -e "${YELLOW}4. Access Your Panel:${NC}"
if [ "$SSL_INSTALLED" = true ]; then
    echo -e "   🌐 URL: ${GREEN}https://$DOMAIN${NC}"
else
    echo -e "   🌐 URL: ${GREEN}http://$DOMAIN${NC} (or https:// after SSL setup)"
fi
echo -e "   🔐 Admin Password: ${GREEN}${ADMIN_PASS}${NC}"
echo ""

# Useful commands
echo -e "${CYAN}📝 Useful Commands:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Check status:     ${CYAN}sudo systemctl status proxy-panel${NC}"
echo -e "  View logs:        ${CYAN}sudo journalctl -u proxy-panel -f${NC}"
echo -e "  Restart service:  ${CYAN}sudo systemctl restart proxy-panel${NC}"
echo -e "  Check Nginx:      ${CYAN}sudo systemctl status nginx${NC}"
echo ""

# Service status
echo -e "${CYAN}🔍 Service Status:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
systemctl is-active proxy-panel > /dev/null 2>&1 && echo -e "  Proxy Panel: ${GREEN}● Running${NC}" || echo -e "  Proxy Panel: ${RED}● Not Running${NC}"
systemctl is-active nginx > /dev/null 2>&1 && echo -e "  Nginx:        ${GREEN}● Running${NC}" || echo -e "  Nginx:        ${RED}● Not Running${NC}"
systemctl is-active 3proxy > /dev/null 2>&1 && echo -e "  3proxy:       ${GREEN}● Running${NC}" || echo -e "  3proxy:       ${RED}● Not Running${NC}"
echo ""

echo -e "${GREEN}✨ Installation completed successfully!${NC}"
echo ""

