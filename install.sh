#!/usr/bin/env bash
# DIAAS-SEC — Automated Install Script
# Tested on: Ubuntu 20.04, 22.04, 24.04 / Debian 11, 12
# For RHEL/Rocky/Arch/openSUSE — see README for manual distro-specific steps
# Run as root or with sudo: sudo bash install.sh

set -euo pipefail

REPO_URL="https://github.com/indranilroy99/soc-training-lab.git"
INSTALL_DIR="/var/www/diaas-sec"
VHOST_CONF="/etc/apache2/sites-available/diaas-sec.conf"
APP_NAME="DIAAS-SEC"

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || error "Run as root or with sudo."
}

detect_distro() {
  if command -v apt-get &>/dev/null; then
    DISTRO="debian"
  elif command -v dnf &>/dev/null; then
    DISTRO="rhel"
  elif command -v pacman &>/dev/null; then
    DISTRO="arch"
  elif command -v zypper &>/dev/null; then
    DISTRO="suse"
  else
    error "Unsupported distro. Install apache2 and git manually, then re-run."
  fi
  info "Detected package manager: $DISTRO"
}

# ─────────────────────────────────────────────
# Step 1 — Install dependencies
# ─────────────────────────────────────────────
install_deps() {
  info "Installing apache2 and git..."
  case "$DISTRO" in
    debian)
      apt-get update -qq
      apt-get install -y apache2 git
      APACHE_SERVICE="apache2"
      APACHE_SITES_ENABLED="/etc/apache2/sites-enabled"
      ;;
    rhel)
      dnf install -y httpd git
      APACHE_SERVICE="httpd"
      VHOST_CONF="/etc/httpd/conf.d/diaas-sec.conf"
      APACHE_SITES_ENABLED=""   # httpd loads all conf.d automatically
      ;;
    arch)
      pacman -Sy --noconfirm apache git
      APACHE_SERVICE="httpd"
      VHOST_CONF="/etc/httpd/conf/extra/diaas-sec.conf"
      APACHE_SITES_ENABLED=""
      ;;
    suse)
      zypper install -y apache2 git
      APACHE_SERVICE="apache2"
      APACHE_SITES_ENABLED=""
      ;;
  esac
  info "Dependencies installed."
}

# ─────────────────────────────────────────────
# Step 2 — Clone repo
# ─────────────────────────────────────────────
clone_repo() {
  # Mark directory safe for git operations run as root (avoids "dubious ownership" error)
  git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true

  if [ -d "$INSTALL_DIR/.git" ]; then
    warn "$INSTALL_DIR already exists — pulling latest instead of cloning."
    git -C "$INSTALL_DIR" pull origin main
  else
    info "Cloning $APP_NAME to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
  fi
}

# ─────────────────────────────────────────────
# Step 3 — Permissions
# ─────────────────────────────────────────────
set_permissions() {
  info "Setting permissions..."
  # Determine web server user
  if id www-data &>/dev/null; then
    WEB_USER="www-data"
  elif id apache &>/dev/null; then
    WEB_USER="apache"
  elif id http &>/dev/null; then
    WEB_USER="http"
  else
    WEB_USER="nobody"
    warn "Could not detect web user — falling back to 'nobody'"
  fi

  # Give web user ownership of app files, but keep .git owned by root
  # so future `sudo git pull` works without the dubious-ownership error
  chown -R "$WEB_USER":"$WEB_USER" "$INSTALL_DIR"
  chown -R root:root "$INSTALL_DIR/.git"
  chmod -R 755 "$INSTALL_DIR"
  info "App files owner: $WEB_USER  |  .git owner: root"
}

# ─────────────────────────────────────────────
# Step 4 — Virtual host config
# ─────────────────────────────────────────────
write_vhost() {
  info "Writing virtual host config to $VHOST_CONF..."
  mkdir -p "$(dirname "$VHOST_CONF")"
  cat > "$VHOST_CONF" << EOF
<VirtualHost *:80>
    DocumentRoot $INSTALL_DIR
    <Directory $INSTALL_DIR>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>
    ErrorLog /var/log/${APACHE_SERVICE}/diaas-sec-error.log
    CustomLog /var/log/${APACHE_SERVICE}/diaas-sec-access.log combined
</VirtualHost>
EOF

  # Debian/Ubuntu: enable site, disable default
  if [ "$DISTRO" = "debian" ]; then
    a2ensite diaas-sec.conf
    a2dissite 000-default.conf 2>/dev/null || true
  fi
}

# ─────────────────────────────────────────────
# Step 5 — Enable and start Apache
# ─────────────────────────────────────────────
start_apache() {
  info "Enabling and starting $APACHE_SERVICE..."
  systemctl enable "$APACHE_SERVICE"
  systemctl restart "$APACHE_SERVICE"
}

# ─────────────────────────────────────────────
# Step 6 — Verify
# ─────────────────────────────────────────────
verify() {
  sleep 1
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    info "Verification passed — HTTP $HTTP_CODE"
  else
    warn "HTTP $HTTP_CODE returned from localhost. Check Apache logs:"
    warn "  sudo journalctl -u $APACHE_SERVICE -n 30"
  fi
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
main() {
  echo ""
  echo "  ██████╗ ██╗ █████╗ ███████╗███████╗    ███████╗███████╗ ██████╗"
  echo "  ██╔══██╗██║██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██╔════╝"
  echo "  ██║  ██║██║███████║███████╗███████╗    ███████╗█████╗  ██║"
  echo "  ██║  ██║██║██╔══██║╚════██║╚════██║    ╚════██║██╔══╝  ██║"
  echo "  ██████╔╝██║██║  ██║███████║███████║    ███████║███████╗╚██████╗"
  echo "  ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝"
  echo ""
  echo "  Security Operations Platform — Install"
  echo "  ──────────────────────────────────────"
  echo ""

  require_root
  detect_distro
  install_deps
  clone_repo
  set_permissions
  write_vhost
  start_apache
  verify

  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "<server-ip>")
  echo ""
  echo -e "${GREEN}  ✓ DIAAS-SEC deployed successfully${NC}"
  echo "  Access: http://${SERVER_IP}"
  echo "  Logs:   /var/log/${APACHE_SERVICE}/diaas-sec-error.log"
  echo "  Update: cd $INSTALL_DIR && sudo git pull origin main && sudo systemctl reload $APACHE_SERVICE"
  echo ""
}

main "$@"
