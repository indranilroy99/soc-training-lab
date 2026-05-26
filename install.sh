#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════
#  DIAAS-SEC Platform — Installer
#  Supports: macOS (Mac mini), Ubuntu/Debian, RHEL/CentOS
# ══════════════════════════════════════════════════════════
set -e

REPO="https://github.com/indranilroy99/soc-training-lab"
INSTALL_DIR="$HOME/diaas-sec"
NODE_MIN=18
PORT=3000

# ── Colours ───────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ██████╗ ██╗ █████╗  █████╗ ███████╗      ███████╗███████╗ ██████╗
  ██╔══██╗██║██╔══██╗██╔══██╗██╔════╝      ██╔════╝██╔════╝██╔════╝
  ██║  ██║██║███████║███████║███████╗█████╗███████╗█████╗  ██║
  ██║  ██║██║██╔══██║██╔══██║╚════██║╚════╝╚════██║██╔══╝  ██║
  ██████╔╝██║██║  ██║██║  ██║███████║      ███████║███████╗╚██████╗
  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝      ╚══════╝╚══════╝ ╚═════╝
BANNER
echo -e "${RESET}"
echo -e "  ${BOLD}Security Operations Training Platform${RESET}"
echo -e "  Installer v2.0"
echo ""

# ── Detect OS ─────────────────────────────────────────────
detect_os() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
  elif [ -f /etc/debian_version ]; then
    OS="debian"
  elif [ -f /etc/redhat-release ]; then
    OS="rhel"
  else
    OS="unknown"
  fi
  info "Detected OS: $OS"
}

# ── Check / Install Node.js ───────────────────────────────
check_node() {
  if command -v node &>/dev/null; then
    NODE_VER=$(node -e "process.stdout.write(process.versions.node.split('.')[0])")
    if [ "$NODE_VER" -ge "$NODE_MIN" ]; then
      success "Node.js $NODE_VER found"
      return 0
    else
      warn "Node.js $NODE_VER is too old (need $NODE_MIN+). Installing newer version..."
    fi
  else
    info "Node.js not found. Installing..."
  fi

  case "$OS" in
    macos)
      if ! command -v brew &>/dev/null; then
        info "Installing Homebrew first..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      fi
      brew install node
      ;;
    debian)
      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
      sudo apt-get install -y nodejs
      ;;
    rhel)
      curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
      sudo yum install -y nodejs
      ;;
    *)
      error "Cannot auto-install Node.js on this OS. Install Node.js $NODE_MIN+ manually from https://nodejs.org then re-run."
      ;;
  esac
  success "Node.js installed: $(node --version)"
}

# ── Check git ─────────────────────────────────────────────
check_git() {
  if ! command -v git &>/dev/null; then
    case "$OS" in
      macos)   brew install git ;;
      debian)  sudo apt-get install -y git ;;
      rhel)    sudo yum install -y git ;;
      *)       error "git not found. Install it manually." ;;
    esac
  fi
  success "git found: $(git --version)"
}

# ── Clone or update ───────────────────────────────────────
setup_repo() {
  if [ -d "$INSTALL_DIR/.git" ]; then
    info "Existing install found at $INSTALL_DIR — pulling latest..."
    git -C "$INSTALL_DIR" pull origin main
  else
    info "Cloning repository to $INSTALL_DIR ..."
    git clone "$REPO" "$INSTALL_DIR"
  fi
  success "Repository ready at $INSTALL_DIR"
}

# ── Install npm deps ──────────────────────────────────────
install_deps() {
  info "Installing Node.js dependencies..."
  cd "$INSTALL_DIR"
  npm install --omit=dev --silent
  success "Dependencies installed (better-sqlite3, bcryptjs)"
}

# ── Seed database ─────────────────────────────────────────
seed_db() {
  cd "$INSTALL_DIR"
  if [ -f "database/diaas.db" ]; then
    warn "Database already exists. Skipping seed (run 'node database/seed.js' manually to re-seed)."
  else
    info "Seeding database..."
    node database/seed.js
    success "Database seeded — 1 admin + 10 analysts + 6 labs"
  fi
}

# ── macOS launchd service ─────────────────────────────────
install_macos_service() {
  PLIST_PATH="$HOME/Library/LaunchAgents/com.diaas-sec.plist"
  NODE_BIN=$(which node)

  cat > "$PLIST_PATH" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.diaas-sec</string>
  <key>ProgramArguments</key>
  <array>
    <string>${NODE_BIN}</string>
    <string>${INSTALL_DIR}/server.js</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PORT</key>
    <string>${PORT}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${INSTALL_DIR}/logs/server.log</string>
  <key>StandardErrorPath</key>
  <string>${INSTALL_DIR}/logs/error.log</string>
</dict>
</plist>
PLIST

  mkdir -p "$INSTALL_DIR/logs"
  launchctl unload "$PLIST_PATH" 2>/dev/null || true
  launchctl load "$PLIST_PATH"
  success "macOS launchd service installed — starts automatically on login"
}

# ── Linux systemd service ─────────────────────────────────
install_linux_service() {
  NODE_BIN=$(which node)
  CURRENT_USER=$(whoami)

  sudo tee /etc/systemd/system/diaas-sec.service > /dev/null << UNIT
[Unit]
Description=DIAAS-SEC Training Platform
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${NODE_BIN} ${INSTALL_DIR}/server.js
Restart=on-failure
RestartSec=5
Environment=PORT=${PORT}
StandardOutput=append:${INSTALL_DIR}/logs/server.log
StandardError=append:${INSTALL_DIR}/logs/error.log

[Install]
WantedBy=multi-user.target
UNIT

  mkdir -p "$INSTALL_DIR/logs"
  sudo systemctl daemon-reload
  sudo systemctl enable diaas-sec
  sudo systemctl restart diaas-sec
  success "systemd service installed and started — auto-starts on boot"
}

# ── Print local IP ────────────────────────────────────────
get_local_ip() {
  if [[ "$OS" == "macos" ]]; then
    IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "localhost")
  else
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
  fi
  echo "$IP"
}

# ── Main ──────────────────────────────────────────────────
main() {
  detect_os
  check_git
  check_node
  setup_repo
  install_deps
  seed_db

  # Install service
  case "$OS" in
    macos)
      read -p "$(echo -e "${YELLOW}Install as a background service (auto-start on login)? [Y/n]: ${RESET}")" INSTALL_SVC
      if [[ "${INSTALL_SVC:-Y}" =~ ^[Yy]$ ]]; then
        install_macos_service
      else
        warn "Skipping service install. Start manually with: cd $INSTALL_DIR && node server.js"
      fi
      ;;
    debian|rhel)
      read -p "$(echo -e "${YELLOW}Install as a systemd service (auto-start on boot)? [Y/n]: ${RESET}")" INSTALL_SVC
      if [[ "${INSTALL_SVC:-Y}" =~ ^[Yy]$ ]]; then
        install_linux_service
      else
        warn "Skipping service install. Start manually with: cd $INSTALL_DIR && node server.js"
      fi
      ;;
  esac

  # Done
  LOCAL_IP=$(get_local_ip)
  echo ""
  echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
  echo -e "${GREEN}${BOLD}  DIAAS-SEC is running!${RESET}"
  echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
  echo ""
  echo -e "  ${BOLD}Platform URL:${RESET}   http://${LOCAL_IP}:${PORT}"
  echo -e "  ${BOLD}Admin Panel:${RESET}    http://${LOCAL_IP}:${PORT}/admin"
  echo -e "  ${BOLD}Analyst View:${RESET}   http://${LOCAL_IP}:${PORT}/analyst"
  echo ""
  echo -e "  ${BOLD}Default Credentials:${RESET}"
  echo -e "  Admin   →  username: ${CYAN}admin${RESET}        password: ${CYAN}Admin@2024${RESET}"
  echo -e "  Analyst →  username: ${CYAN}analyst_01${RESET}   password: ${CYAN}Analyst@2024${RESET}"
  echo -e "             (analyst_01 through analyst_10 — all same default password)"
  echo ""
  echo -e "  ${YELLOW}Change all passwords via the Admin panel before sharing with users.${RESET}"
  echo ""
  echo -e "  ${BOLD}Logs:${RESET}  $INSTALL_DIR/logs/server.log"
  echo ""
}

main "$@"
