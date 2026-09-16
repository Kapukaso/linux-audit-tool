#!/usr/bin/env bash
# ==============================================================================
# Script Name: cleanup_lab.sh
# Author:      Kartik Soni
# Description: Removes vulnerable drop-in configurations, restores standard
#              file permissions, and cleans up the test VM environment.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Enforce Root Privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log_error "This script must be executed as root (UID 0). Use: sudo $0"
    exit 1
fi

log_info "Initiating cleanup of vulnerable lab test configurations..."

# 2. Remove SSH Drop-in
SSH_DROPIN="/etc/ssh/sshd_config.d/99-vulnerable-lab.conf"
if [ -f "$SSH_DROPIN" ]; then
    rm -f "$SSH_DROPIN"
    log_success "Removed SSH vulnerable drop-in config ($SSH_DROPIN)."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload ssh || systemctl reload sshd || true
    fi
fi

# 3. Restore POSIX Permissions
chmod 0644 /etc/passwd 2>/dev/null || true
chmod 0600 /etc/shadow 2>/dev/null || true
chmod 0600 /etc/gshadow 2>/dev/null || true
chmod 0644 /etc/group 2>/dev/null || true
chmod 0644 /etc/crontab 2>/dev/null || true

# Remove world-writable test files
rm -f /tmp/vulnerable_world_writable.tmp /var/tmp/vulnerable_world_writable.tmp
log_success "Restored standard POSIX file permissions (0644/0600) and removed temp files."

# 4. Remove Sysctl Drop-in
SYSCTL_DROPIN="/etc/sysctl.d/99-vulnerable-lab.conf"
if [ -f "$SYSCTL_DROPIN" ]; then
    rm -f "$SYSCTL_DROPIN"
    log_success "Removed sysctl vulnerable drop-in config ($SYSCTL_DROPIN)."
    if command -v sysctl >/dev/null 2>&1; then
        sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1 || true
        sysctl --system >/dev/null 2>&1 || true
    fi
fi

# 5. Restore login.defs if backup exists
if [ -f /etc/login.defs.bak ]; then
    mv /etc/login.defs.bak /etc/login.defs
    log_success "Restored original /etc/login.defs configuration."
fi

# 6. Re-Lock Root Account and Restart Security Daemons
passwd -l root 2>/dev/null || true
log_success "Root account locked."

if command -v systemctl >/dev/null 2>&1; then
    systemctl start rsyslog 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
fi
log_success "Security daemons restarted."

echo ""
log_success "====================================================================="
log_success "  LAB CLEANUP COMPLETE!                                             "
log_success "  Vulnerable test artifacts have been safely removed.              "
log_success "====================================================================="
