#!/usr/bin/env bash
# ==============================================================================
# Script Name: setup_vulnerable_lab.sh
# Author:      Kartik Soni
# Description: Intentionally misconfigures an Ubuntu/Debian target VM to simulate
#              a vulnerable system for testing secureaudit pre/post hardening metrics.
# WARNING:     DO NOT RUN THIS SCRIPT ON PRODUCTION SYSTEMS!
#              Run only inside isolated test virtual machines or containers.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Enforce Root Privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log_error "This script must be executed as root (UID 0). Use: sudo $0"
    exit 1
fi

log_warn "====================================================================="
log_warn "  WARNING: PREPARING VULNERABLE TEST ENVIRONMENT FOR SECUREAUDIT     "
log_warn "  This script will inject insecure configurations into this host.   "
log_warn "====================================================================="

# 2. Inject Insecure SSH Configuration
log_info "1/6 Injecting insecure SSH server directives..."
SSH_DROPIN="/etc/ssh/sshd_config.d/99-vulnerable-lab.conf"
mkdir -p /etc/ssh/sshd_config.d

cat << 'EOF' > "$SSH_DROPIN"
# Insecure test directives created by setup_vulnerable_lab.sh
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
Protocol 1,2
EOF
chmod 0644 "$SSH_DROPIN"

if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh || systemctl reload sshd || true
fi
log_success "SSH server misconfigured: Root login & empty passwords enabled."

# 3. Inject Insecure File Permissions
log_info "2/6 Relaxing POSIX permissions on critical system files..."
chmod 0666 /etc/passwd 2>/dev/null || true
chmod 0644 /etc/shadow 2>/dev/null || true
chmod 0644 /etc/gshadow 2>/dev/null || true
chmod 0666 /etc/group 2>/dev/null || true
chmod 0777 /etc/crontab 2>/dev/null || true

# Create world-writable files in /tmp and /var/tmp
touch /tmp/vulnerable_world_writable.tmp /var/tmp/vulnerable_world_writable.tmp
chmod 0777 /tmp/vulnerable_world_writable.tmp /var/tmp/vulnerable_world_writable.tmp
log_success "File permissions relaxed: /etc/passwd set to 0666, world-writable temp files created."

# 4. Inject Insecure User Accounts & Policies
log_info "3/6 Modifying user accounts and password expiration policies..."
if [ -f /etc/login.defs ]; login_defs_bak="/etc/login.defs.bak"; [ ! -f "$login_defs_bak" ] && cp /etc/login.defs "$login_defs_bak"; sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs; fi

# Unlock root password if locked
passwd -u root 2>/dev/null || true
log_success "User security relaxed: PASS_MAX_DAYS set to 99999, root account unlocked."

# 5. Disable Host Firewall (UFW)
log_info "4/6 Disabling host firewall (UFW)..."
if command -v ufw >/dev/null 2>&1; then
    ufw --force disable || true
    log_success "UFW firewall disabled."
else
    log_warn "UFW is not installed on this system."
fi

# 6. Inject Insecure Sysctl Kernel Parameters
log_info "5/6 Setting insecure sysctl network parameters..."
SYSCTL_DROPIN="/etc/sysctl.d/99-vulnerable-lab.conf"
cat << 'EOF' > "$SYSCTL_DROPIN"
# Insecure network settings for lab testing
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.default.accept_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.log_martians = 0
EOF
chmod 0644 "$SYSCTL_DROPIN"

if command -v sysctl >/dev/null 2>&1; then
    sysctl -p "$SYSCTL_DROPIN" >/dev/null 2>&1 || true
fi
log_success "Kernel parameters misconfigured: IP forwarding & redirects enabled."

# 7. Stop Security Daemons
log_info "6/6 Stopping security logging daemons..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop rsyslog 2>/dev/null || true
    systemctl stop auditd 2>/dev/null || true
fi
log_success "Security daemons stopped."

echo ""
log_success "====================================================================="
log_success "  VULNERABLE LAB ENVIRONMENT SETUP COMPLETE!                        "
log_success "  You can now run:                                                   "
log_success "    python3 secureaudit.py audit                                     "
log_success "    python3 secureaudit.py harden --dry-run                          "
log_success "====================================================================="
