#!/bin/bash

# ==================================================
# CyberPatriots Security Hardening Script for Linux Mint
# Competition-Optimized Version 2.1 (SAFE)
# ==================================================
# Design goals:
#  - Sequential APT ops (no lock contention)
#  - Sudoers edits validated (visudo) + temporary rescue rule
#  - PAM uses pam_faillock (fallback to pam_tally2) + pwhistory
#  - SSH hardening without deprecated directives; restart guarded
#  - Safe cleanup in /tmp (no dot-glob footguns)
#  - Idempotent service checks; scenario-aware required services
#  - Backups + one-click REVERT script
#  - Triple-checked: current admin cannot be locked out
# ==================================================

set -Eeuo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ================= COMPETITION CONFIG =================
COMPETITION_MODE="yes"        # yes = auto actions, no = prompt for destructive steps
SCENARIO="general"            # general | web_server | file_server | workstation
DISABLE_IPV6="no"             # no is safer for networking unless README says otherwise

# ------------------------------
# Root check
# ------------------------------
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[-] Run as root (sudo).${NC}"; exit 1
fi

# ------------------------------
# Detect current user & tty
# ------------------------------
CURRENT_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-}" || who | awk 'NR==1{print $1}')
if [[ -z "${CURRENT_USER}" ]]; then
  echo -e "${RED}[-] Could not determine invoking user. Aborting for safety.${NC}"; exit 1
fi
CURRENT_TTY=$(tty || true)

# Banner
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   CyberPatriots Speed Hardening Script v2.1   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}[*] Competition Mode: ${COMPETITION_MODE}${NC}"
echo -e "${BLUE}[*] Scenario Type: ${SCENARIO}${NC}"
echo -e "${BLUE}[*] Acting user: ${CURRENT_USER}  TTY: ${CURRENT_TTY}${NC}\n"

# ------------------------------
# Logging & backups
# ------------------------------
STAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/var/log/cyberpatriots_hardening_${STAMP}.log"
BACKUP_DIR="/root/cyberpatriots_backups_${STAMP}"
mkdir -p "${BACKUP_DIR}"
exec > >(tee -a "${LOGFILE}") 2>&1
umask 027
trap 'echo -e "\n${RED}[!] Error on line $LINENO. See ${LOGFILE}.${NC}"' ERR

echo -e "${GREEN}[+] Logging to: ${LOGFILE}${NC}"
echo -e "${GREEN}[+] Backups in: ${BACKUP_DIR}${NC}\n"

make_backup() {
  local src="$1" dst
  if [[ -e "$src" ]]; then
    dst="${BACKUP_DIR}${src}"
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

# ------------------------------
# Config vars (customize from README)
# ------------------------------
AUTHORIZED_USERS=("${CURRENT_USER}" "root")
ADMINISTRATORS=("${CURRENT_USER}")

# Group authorizations (enforced later)
declare -A GROUPS_AUTHORIZED=(
  ["adm"]="syslog,${CURRENT_USER}"
  ["sudo"]="${CURRENT_USER}"
)

# System users to set nologin
declare -A SYSTEM_USERS=(
  ["daemon"]="/usr/sbin/nologin"
  ["bin"]="/usr/sbin/nologin"
  ["sys"]="/usr/sbin/nologin"
  ["sync"]="/bin/sync"
  ["games"]="/usr/sbin/nologin"
  ["man"]="/usr/sbin/nologin"
  ["lp"]="/usr/sbin/nologin"
  ["mail"]="/usr/sbin/nologin"
  ["news"]="/usr/sbin/nologin"
  ["uucp"]="/usr/sbin/nologin"
  ["proxy"]="/usr/sbin/nologin"
  ["www-data"]="/usr/sbin/nologin"
  ["backup"]="/usr/sbin/nologin"
  ["list"]="/usr/sbin/nologin"
  ["irc"]="/usr/sbin/nologin"
  ["gnats"]="/usr/sbin/nologin"
  ["nobody"]="/usr/sbin/nologin"
)

# Password policy
PASS_MAX_DAYS=90
PASS_MIN_DAYS=7
PASS_WARN_AGE=14
MIN_PASS_LENGTH=12

# Services
svc_exists() { systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx "${1}.service"; }
svc_active() { systemctl is-active --quiet "$1"; }
REQUIRED_SERVICES=()
if [[ "$SCENARIO" == "web_server" ]]; then
  if svc_exists apache2 && (svc_active apache2 || dpkg -l | grep -q '^ii\s\+apache2'); then
    REQUIRED_SERVICES=("apache2")
  elif svc_exists nginx && (svc_active nginx || dpkg -l | grep -q '^ii\s\+nginx'); then
    REQUIRED_SERVICES=("nginx")
  fi
elif [[ "$SCENARIO" == "file_server" ]]; then
  REQUIRED_SERVICES=("smbd" "nmbd")
fi
ALWAYS_DISABLE=(
  "avahi-daemon" "cups" "bluetooth" "cups-browsed" "whoopsie"
  "speech-dispatcher" "modemmanager" "mobile-broadband-provider-info"
)
SUSPICIOUS_SERVICES=(
  "vsftpd" "pure-ftpd" "proftpd" "apache2" "nginx" "lighttpd"
  "mysql" "postgresql" "smbd" "nmbd" "snmpd" "xinetd" "inetd"
  "rpcbind" "bind9" "dnsmasq" "slapd" "nfs-kernel-server" "telnet"
)

# Files to remove/quarantine (optional phase)
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac" "*.mov" "*.wmv" "*.aac" "*.wav")

# Hacker tools to remove
HACKER_TOOLS=(
  "john" "john-the-ripper" "hydra" "hydra-gtk" "nmap" "zenmap" "metasploit"
  "metasploit-framework" "wireshark" "tshark" "sqlmap" "aircrack-ng"
  "ophcrack" "nikto" "medusa" "burpsuite" "ettercap" "ettercap-text-only"
  "kismet" "netcat" "nc" "netcat-traditional" "netcat-openbsd" "hashcat"
  "rainbowcrack" "dsniff" "fcrackzip" "lcrack" "crack" "freeciv"
  "minetest" "minetest-server" "wesnoth" "remmina" "telnet" "ftp"
)

# ------------------------------
# Pre-flight backups (before touching anything)
# ------------------------------
for f in \
  /etc/passwd /etc/group /etc/shadow /etc/gshadow \
  /etc/login.defs /etc/security/pwquality.conf \
  /etc/pam.d/common-auth /etc/pam.d/common-password \
  /etc/ssh/sshd_config /etc/sysctl.conf \
  /etc/crontab \
  ; do make_backup "$f"; done

# backup directories
[[ -d /etc/sudoers.d ]] && { mkdir -p "${BACKUP_DIR}/etc"; tar -C / -czf "${BACKUP_DIR}/etc/sudoers.d.tgz" etc/sudoers.d; }
[[ -d /etc/lightdm ]] && { mkdir -p "${BACKUP_DIR}/etc"; tar -C / -czf "${BACKUP_DIR}/etc/lightdm.tgz" etc/lightdm; }
[[ -d /etc/ufw ]] && { mkdir -p "${BACKUP_DIR}/etc"; tar -C / -czf "${BACKUP_DIR}/etc/ufw.tgz" etc/ufw; }

# ------------------------------
# REVERT script (can be run anytime)
# ------------------------------
cat > "${BACKUP_DIR}/REVERT.sh" <<'EOS'
#!/bin/bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi
restore_file(){ src="$1"; b="__BACKUP_DIR__${src}"; [[ -e "$b" ]] && cp -a "$b" "$src"; }
restore_tar(){ t="$1"; dest="$2"; [[ -f "__BACKUP_DIR__${t}" ]] && { tar -C / -xzf "__BACKUP_DIR__${t}"; } }

# Replace placeholders
BACKUP_DIR="__BACKUP_DIR__"

restore_file /etc/passwd
restore_file /etc/group
restore_file /etc/shadow
restore_file /etc/gshadow
restore_file /etc/login.defs
restore_file /etc/security/pwquality.conf
restore_file /etc/pam.d/common-auth
restore_file /etc/pam.d/common-password
restore_file /etc/ssh/sshd_config
restore_file /etc/sysctl.conf
restore_file /etc/crontab

restore_tar /etc/sudoers.d.tgz /etc/sudoers.d
restore_tar /etc/lightdm.tgz /etc/lightdm
restore_tar /etc/ufw.tgz /etc/ufw

# validate sudoers
if ! visudo -cf /etc/sudoers >/dev/null 2>&1; then echo "WARNING: /etc/sudoers syntax check failed"; fi

# reload services
sysctl -p || true
systemctl restart ssh || true
ufw --force disable || true
ufw --force enable || true

# ensure invoking user regains sudo (best effort)
CU=$(logname 2>/dev/null || echo "${SUDO_USER:-}")
if [[ -n "$CU" ]]; then usermod -aG sudo "$CU" || true; fi

echo "Revert complete. Some services may require manual review."
EOS
sed -i "s|__BACKUP_DIR__|${BACKUP_DIR}|g" "${BACKUP_DIR}/REVERT.sh"
chmod 700 "${BACKUP_DIR}/REVERT.sh"
echo -e "${GREEN}[+] REVERT helper created: ${BACKUP_DIR}/REVERT.sh${NC}"

# ==================================================
# PHASE 1: APT (sequential + prerequisites)
# ==================================================
export DEBIAN_FRONTEND=noninteractive

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          PHASE 1: PACKAGE MANAGEMENT          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

echo -e "${YELLOW}[*] Updating and installing prerequisites...${NC}"
apt-get update -y
# preinstall dependencies we use later
apt-get install -y ufw libpam-pwquality auditd audispd-plugins || true

echo -e "${YELLOW}[*] Upgrading system packages...${NC}"
apt-get upgrade -y
apt-get autoremove -y
apt-get autoclean -y

# ==================================================
# PHASE 2: SAFETY – SUDOERS RESCUE + VALIDATION
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      PHASE 2: SUDOERS SAFETY & CLEANUP        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

# Temporary rescue rule to prevent lockout during edits
RESCUE_FILE="/etc/sudoers.d/99-cp-rescue"
if [[ ! -f "$RESCUE_FILE" ]]; then
  echo "${CURRENT_USER} ALL=(ALL:ALL) ALL" > "$RESCUE_FILE"
  chown root:root "$RESCUE_FILE"; chmod 0440 "$RESCUE_FILE"
fi
if ! visudo -cf /etc/sudoers >/dev/null 2>&1; then
  echo -e "${RED}[!] Sudoers invalid even before changes—fix manually, then rerun.${NC}"; exit 1
fi

# Remove NOPASSWD safely
cp -a /etc/sudoers "${BACKUP_DIR}/sudoers.pre-nopasswd.bak"
sed -Ei 's/(,?\s*)NOPASSWD:/\1/g' /etc/sudoers
if [[ -d /etc/sudoers.d ]]; then
  for f in /etc/sudoers.d/*; do [[ -f "$f" ]] && sed -Ei 's/(,?\s*)NOPASSWD:/\1/g' "$f"; done
fi
if ! visudo -cf /etc/sudoers >/dev/null 2>&1; then
  echo -e "${RED}[!] visudo check failed—restoring sudoers!${NC}"
  cp -a "${BACKUP_DIR}/sudoers.pre-nopasswd.bak" /etc/sudoers
fi

echo -e "${YELLOW}[*] Ensuring ${CURRENT_USER} is in sudo group...${NC}"
usermod -aG sudo "${CURRENT_USER}" || true

# ==================================================
# PHASE 3: USER MANAGEMENT
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            PHASE 3: USER MANAGEMENT           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

# Lock system users to nologin where applicable
for u in "${!SYSTEM_USERS[@]}"; do
  if id "$u" &>/dev/null; then usermod -s "${SYSTEM_USERS[$u]}" "$u" 2>/dev/null || true; fi
done

echo -e "${YELLOW}[*] Removing unauthorized human users (UID>=1000) except protected...${NC}"
PROTECT_USERS=("${CURRENT_USER}" "root")
DELETED_USERS=0
for u in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  skip=false
  for p in "${PROTECT_USERS[@]}"; do [[ "$u" == "$p" ]] && skip=true; done
  if ! $skip && [[ " ${AUTHORIZED_USERS[*]} " != *" $u "* ]]; then
    if [[ "$COMPETITION_MODE" == "yes" ]]; then
      pkill -u "$u" 2>/dev/null || true
      userdel -r "$u" 2>/dev/null && ((DELETED_USERS++)) || true
      echo -e "${GREEN}[+] Deleted unauthorized user: $u${NC}"
    else
      read -rp "Delete unauthorized user $u? (y/n): " ans; [[ "$ans" == "y" ]] && { pkill -u "$u" 2>/dev/null; userdel -r "$u" 2>/dev/null && ((DELETED_USERS++)); }
    fi
  fi
done
echo -e "${GREEN}[+] Deleted $DELETED_USERS unauthorized users${NC}"

# Sudo group pruning (keep only ADMINISTRATORS)
echo -e "${YELLOW}[*] Pruning sudo group membership...${NC}"
CUR_SUDO=$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')
for u in $CUR_SUDO; do
  keep=false; for a in "${ADMINISTRATORS[@]}"; do [[ "$u" == "$a" ]] && keep=true; done
  if ! $keep; then deluser "$u" sudo 2>/dev/null || true; fi
done

# Password aging for all real users
for u in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  chage --maxdays "$PASS_MAX_DAYS" --mindays "$PASS_MIN_DAYS" --warndays "$PASS_WARN_AGE" "$u" 2>/dev/null || true
done

# Secure home directories
for d in /home/*; do
  [[ -d "$d" ]] || continue
  u=$(basename "$d")
  if id "$u" &>/dev/null; then chmod 750 "$d"; chown "$u:$u" "$d"; else echo -e "${YELLOW}[!] Orphaned home: $d${NC}"; [[ "$COMPETITION_MODE" == "yes" ]] && rm -rf "$d"; fi
done

# Enforce group membership exactly per GROUPS_AUTHORIZED
for grp in "${!GROUPS_AUTHORIZED[@]}"; do
  if getent group "$grp" >/dev/null; then
    IFS=',' read -r -a members <<< "${GROUPS_AUTHORIZED[$grp]}"
    gpasswd -M "$(printf '%s,' "${members[@]}" | sed 's/,$//')" "$grp" 2>/dev/null || true
    echo -e "${GREEN}[+] $grp => ${GROUPS_AUTHORIZED[$grp]}${NC}"
  fi
done

# ==================================================
# PHASE 4: PAM (faillock + pwhistory + pwquality)
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      PHASE 4: PAM & PASSWORD HARDENING        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

# login.defs
make_backup /etc/login.defs
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${PASS_MAX_DAYS}/" /etc/login.defs || echo "PASS_MAX_DAYS   ${PASS_MAX_DAYS}" >> /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${PASS_MIN_DAYS}/" /etc/login.defs || echo "PASS_MIN_DAYS   ${PASS_MIN_DAYS}" >> /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${PASS_WARN_AGE}/" /etc/login.defs || echo "PASS_WARN_AGE   ${PASS_WARN_AGE}" >> /etc/login.defs
grep -q '^ENCRYPT_METHOD' /etc/login.defs && sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs || echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs
grep -q '^PASS_MIN_LEN' /etc/login.defs || echo "PASS_MIN_LEN   ${MIN_PASS_LENGTH}" >> /etc/login.defs

# pwquality
cat > /etc/security/pwquality.conf << EOF
# CyberPatriots Password Quality
minlen = ${MIN_PASS_LENGTH}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
usercheck = 1
enforcing = 1
retry = 3
difok = 3
dictcheck = 1
EOF
sed -i '/^remember[[:space:]]*=/d' /etc/security/pwquality.conf || true

echo -e "${YELLOW}[*] Configuring PAM lockout/history...${NC}"
make_backup /etc/pam.d/common-auth
make_backup /etc/pam.d/common-password

if grep -q pam_faillock.so /etc/pam.d/common-auth || [[ -f /lib/security/pam_faillock.so || -f /usr/lib/security/pam_faillock.so ]]; then
  # remove any tally2 remnants
  sed -i '/pam_tally2.so/d' /etc/pam.d/common-auth || true
  grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth || \
    sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800 fail_interval=900' /etc/pam.d/common-auth
  grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth || \
    sed -i '/^auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800 fail_interval=900' /etc/pam.d/common-auth
else
  grep -q 'pam_tally2.so' /etc/pam.d/common-auth || \
    sed -i '1i auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail' /etc/pam.d/common-auth
fi

# password history
if ! grep -q 'pam_pwhistory.so' /etc/pam.d/common-password; then
  sed -i '1i password requisite pam_pwhistory.so remember=5 use_authtok' /etc/pam.d/common-password
fi

# ensure CURRENT_USER is not locked right now
if command -v faillock >/dev/null 2>&1; then faillock --user "${CURRENT_USER}" --reset || true; fi

# ==================================================
# PHASE 5: SERVICE MANAGEMENT
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           PHASE 5: SERVICE MANAGEMENT         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

echo -e "${YELLOW}[*] Disabling non-required services...${NC}"
DISABLED_COUNT=0
for s in "${ALWAYS_DISABLE[@]}"; do
  if svc_exists "$s"; then systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true; ((DISABLED_COUNT++)); echo -e "${GREEN}[+] Disabled $s${NC}"; fi
done

for s in "${SUSPICIOUS_SERVICES[@]}"; do
  if [[ " ${REQUIRED_SERVICES[*]} " == *" $s "* ]]; then echo -e "${BLUE}[*] Keeping required: $s${NC}"; continue; fi
  if svc_exists "$s"; then
    if [[ "$COMPETITION_MODE" == "yes" ]]; then systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true; ((DISABLED_COUNT++)); echo -e "${GREEN}[+] Disabled $s${NC}"; else
      read -rp "Disable $s? (y/n): " ans; [[ "$ans" == "y" ]] && { systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true; ((DISABLED_COUNT++)); }
    fi
  fi
done
echo -e "${GREEN}[+] Disabled $DISABLED_COUNT services${NC}"

# ==================================================
# PHASE 6: REMOVE TOOLS/GAMES
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      PHASE 6: REMOVE MALICIOUS SOFTWARE       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

REMOVED_COUNT=0
for pkg in "${HACKER_TOOLS[@]}"; do
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
    apt-get remove --purge -y "$pkg" 2>/dev/null && ((REMOVED_COUNT++)) || true
    echo -e "${GREEN}[+] Removed: $pkg${NC}"
  fi
done
echo -e "${GREEN}[+] Removed $REMOVED_COUNT packages${NC}"
apt-get autoremove -y 2>/dev/null || true
apt-get autoclean -y 2>/dev/null || true

# ==================================================
# PHASE 7: SSH HARDENING
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             PHASE 7: SSH HARDENING            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

SSH_CONFIG='/etc/ssh/sshd_config'
if [[ -f "$SSH_CONFIG" ]]; then
  make_backup "$SSH_CONFIG"
  echo -e "${YELLOW}[*] Hardening SSH config...${NC}"
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSH_CONFIG"   # keep yes to avoid lockout
  sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
  sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
  sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSH_CONFIG"
  sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' "$SSH_CONFIG"
  sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/' "$SSH_CONFIG"
  sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' "$SSH_CONFIG"
  sed -i 's/^#*StrictModes.*/StrictModes yes/' "$SSH_CONFIG"
  # remove obsolete directives if present
  sed -i '/^#*UsePrivilegeSeparation/d' "$SSH_CONFIG"
  sed -i '/^#*Protocol[[:space:]]\+2/d' "$SSH_CONFIG"
  # AllowUsers includes CURRENT_USER explicitly
  if ! grep -q '^AllowUsers' "$SSH_CONFIG"; then echo "AllowUsers ${CURRENT_USER}" >> "$SSH_CONFIG"; fi
  systemctl restart ssh || { echo -e "${RED}[!] ssh restart failed—reverting sshd_config${NC}"; cp -a "${BACKUP_DIR}/etc/ssh/sshd_config" "$SSH_CONFIG"; systemctl restart ssh || true; }
  echo -e "${GREEN}[+] SSH hardened${NC}"
fi

# ==================================================
# PHASE 8: FIREWALL (UFW)
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        PHASE 8: FIREWALL CONFIGURATION        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

ufw --force disable || true
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw allow 22/tcp comment 'SSH'
if [[ "$SCENARIO" == "web_server" ]]; then
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
elif [[ "$SCENARIO" == "file_server" ]]; then
  ufw allow 139/tcp comment 'SMB'
  ufw allow 445/tcp comment 'SMB'
fi
ufw logging high
ufw --force enable || true

# ==================================================
# PHASE 9: KERNEL HARDENING
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           PHASE 9: KERNEL HARDENING           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

make_backup /etc/sysctl.conf
# Append (idempotent-ish) by filtering existing keys first
apply_sysctl(){ key="$1"; val="$2"; grep -q "^${key}\b" /etc/sysctl.conf && sed -i "s|^${key}.*|${key} = ${val}|" /etc/sysctl.conf || echo "${key} = ${val}" >> /etc/sysctl.conf; }

apply_sysctl net.ipv4.tcp_syncookies 1
apply_sysctl net.ipv4.ip_forward 0
apply_sysctl net.ipv6.conf.all.forwarding 0
apply_sysctl net.ipv4.conf.all.send_redirects 0
apply_sysctl net.ipv4.conf.default.send_redirects 0
apply_sysctl net.ipv4.conf.all.accept_source_route 0
apply_sysctl net.ipv4.conf.default.accept_source_route 0
apply_sysctl net.ipv6.conf.all.accept_source_route 0
apply_sysctl net.ipv4.conf.all.accept_redirects 0
apply_sysctl net.ipv4.conf.default.accept_redirects 0
apply_sysctl net.ipv6.conf.all.accept_redirects 0
apply_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
apply_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
apply_sysctl net.ipv4.conf.all.rp_filter 1
apply_sysctl net.ipv4.conf.default.rp_filter 1
apply_sysctl net.ipv4.conf.all.log_martians 1
apply_sysctl net.ipv4.conf.default.log_martians 1
apply_sysctl kernel.dmesg_restrict 1
apply_sysctl kernel.kptr_restrict 2
apply_sysctl kernel.yama.ptrace_scope 1
apply_sysctl kernel.core_uses_pid 1
apply_sysctl fs.suid_dumpable 0

if [[ "$DISABLE_IPV6" == "yes" ]]; then
  apply_sysctl net.ipv6.conf.all.disable_ipv6 1
  apply_sysctl net.ipv6.conf.default.disable_ipv6 1
  apply_sysctl net.ipv6.conf.lo.disable_ipv6 1
else
  # ensure we don't leave disable flags around
  sed -i '/^net\.ipv6\.conf\..*disable_ipv6/d' /etc/sysctl.conf || true
fi

sysctl -p 2>/dev/null || true

# ==================================================
# PHASE 10: PERMISSIONS & CLEANUP
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     PHASE 10: FILE PERMISSIONS & CLEANUP      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow
chown root:root /etc/passwd /etc/group /etc/crontab /etc/ssh/sshd_config 2>/dev/null || true
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || true
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

# Remove some known-dangerous SUID bits (conservative)
for b in /usr/bin/at /usr/bin/lppasswd /usr/bin/newgrp /usr/bin/wall /usr/bin/write /usr/bin/mount /usr/bin/umount; do
  [[ -f "$b" ]] && chmod u-s "$b" 2>/dev/null || true
done

# Safe temp cleanup
find /tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
find /var/tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
find /dev/shm -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true

# ==================================================
# PHASE 11: MEDIA (optional if not in competition)
# ==================================================
if [[ "$COMPETITION_MODE" == "no" ]]; then
  echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║           PHASE 11: MEDIA QUARANTINE          ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
  QUAR="${BACKUP_DIR}/quarantine_media"; mkdir -p "$QUAR"
  for loc in /home /root /opt; do
    for pat in "${FILE_TYPES_TO_REMOVE[@]}"; do
      find "$loc" -type f -iname "$pat" -exec mv -t "$QUAR" -- {} + 2>/dev/null || true
    done
  done
  echo -e "${GREEN}[+] Media files quarantined to $QUAR${NC}"
else
  echo -e "${YELLOW}[*] Skipping media removal in competition mode${NC}"
fi

# ==================================================
# PHASE 12: AUDIT & MONITORING
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          PHASE 12: AUDIT & MONITORING         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}=== UID 0 Users ===${NC}"; awk -F: '$3 == 0 {print $1}' /etc/passwd

echo -e "\n${YELLOW}=== Sudoers ===${NC}"; getent group sudo | cut -d: -f4

echo -e "\n${YELLOW}=== Cron directories ===${NC}"; ls /etc/cron.* 2>/dev/null | grep -v '\.placeholder' || true
for u in $(cut -f1 -d: /etc/passwd); do crontab -u "$u" -l 2>/dev/null | grep -Ev '^(#|$)' && echo "User: $u"; done

echo -e "\n${YELLOW}=== Listening services ===${NC}"; ss -tulpn | grep LISTEN || true

# auditd enable (points on many images)
systemctl enable --now auditd 2>/dev/null || true

# ==================================================
# FINAL: VALIDATIONS & CLEANUP
# ==================================================

echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              FINAL VALIDATION                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

# Ensure CURRENT_USER has sudo rights
if groups "${CURRENT_USER}" | grep -q '\bsudo\b'; then
  echo -e "${GREEN}[✓] ${CURRENT_USER} is in sudo group${NC}"
else
  echo -e "${RED}[!] Restoring sudo group for ${CURRENT_USER}${NC}"; usermod -aG sudo "${CURRENT_USER}" || true
fi
# Verify sudo listing works (no password required for check)
sudo -l -U "${CURRENT_USER}" >/dev/null 2>&1 || echo -e "${YELLOW}[!] Could not validate sudo -U for ${CURRENT_USER} (may be fine)${NC}"

# If we’re safe, remove the temporary rescue rule
if groups "${CURRENT_USER}" | grep -q '\bsudo\b' && visudo -cf /etc/sudoers >/dev/null 2>&1; then
  rm -f /etc/sudoers.d/99-cp-rescue || true
  echo -e "${GREEN}[+] Removed temporary sudoers rescue file${NC}"
else
  echo -e "${YELLOW}[!] Keeping rescue sudoers file for safety${NC}"
fi

# Scoring checklist
cat > "${BACKUP_DIR}/SCORING_CHECKLIST.txt" << EOF
CYBERPATRIOTS SCORING CHECKLIST
================================
User Management:
  - Current user (${CURRENT_USER}) in sudo: $(groups "${CURRENT_USER}" | grep -q '\bsudo\b' && echo YES || echo NO)
  - Unauthorized users removed: ${DELETED_USERS}
  - Sudo group now: $(getent group sudo | cut -d: -f4)

PAM:
  - Lockout: $(grep -q pam_faillock.so /etc/pam.d/common-auth && echo pam_faillock || echo pam_tally2)
  - Password history: $(grep -q pam_pwhistory.so /etc/pam.d/common-password && echo YES || echo NO)
  - pwquality minlen: ${MIN_PASS_LENGTH}

SSH:
  - PermitRootLogin no: $(grep -Eiq '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config && echo YES || echo NO)
  - PasswordAuthentication yes: $(grep -Eiq '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config && echo YES || echo NO)
  - AllowUsers includes ${CURRENT_USER}: $(grep -Eiq '^\s*AllowUsers.*\b'"${CURRENT_USER}"'\b' /etc/ssh/sshd_config && echo YES || echo NO)

Firewall (UFW):
  - Status: $(ufw status | head -n1)
  - Rules:\n$(ufw status | sed 's/^/    /')

Kernel Hardening:
  - dmesg_restrict=1, kptr_restrict=2, ptrace_scope=1 set

Services:
  - Disabled count: ${DISABLED_COUNT}

Backups & Revert:
  - Backups dir: ${BACKUP_DIR}
  - Revert script: ${BACKUP_DIR}/REVERT.sh
EOF

echo -e "${GREEN}[+] All done. Backups at ${BACKUP_DIR}  |  Revert with: ${BACKUP_DIR}/REVERT.sh${NC}"
