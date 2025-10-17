#!/bin/bash
# ==================================================
# CyberPatriot Mint 21 Hardening Script (Scenario-Tuned)
# Competition-Optimized Version 2.3 (SAFE for README)
# ==================================================
# Scenario mappings:
#  - Mint 21 only; LightDM must remain DM
#  - Install & run Apache; DO NOT over-harden Apache
#  - SSHD is CRITICAL: enabled; all authorized users may SSH
#  - Create/keep ONLY authorized accounts; set admin passwords AS GIVEN
#  - Current auto-login admin's password is NOT changed (toggle below)
#  - Remove hacking tools; quarantine non-work media
#  - Never touch CCS/Scoring client or LightDM
#  - Backups + one-click REVERT; phase summaries + final banner
# ==================================================

# ---- Guards: must run with bash 4+, not sh; normalize CRLF if present ----
if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "This script requires bash 4+. Run: sudo bash ./harden.sh"; exit 1; fi
if [ "$(ps -p $$ -o comm=)" != "bash" ]; then
  echo "Please run with: sudo bash ./harden.sh"; exit 1; fi

set -Eeuo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# ================= COMPETITION CONFIG =================
COMPETITION_MODE="yes"          # yes = auto actions
SCENARIO="web_server"           # per README: Apache must be installed & running
DISABLE_IPV6="no"               # keep IPv6 unless README changes it
MEDIA_QUARANTINE="yes"          # README forbids non-work media -> quarantine
SKIP_CURRENT_ADMIN_PW_CHANGE="yes"  # keep auto-login admin password unchanged

# ------------------------------ Root/User Context ------------------------------
if [[ $EUID -ne 0 ]]; then echo -e "${RED}[-] Run as root (sudo).${NC}"; exit 1; fi
CURRENT_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-}" || who | awk 'NR==1{print $1}')
if [[ -z "${CURRENT_USER}" ]]; then echo -e "${RED}[-] Could not determine invoking user. Aborting for safety.${NC}"; exit 1; fi
CURRENT_TTY=$(tty || true)

echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   CyberPatriot Mint 21 Hardening Script v2.3  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}[*] Competition Mode: ${COMPETITION_MODE}${NC}"
echo -e "${BLUE}[*] Scenario Type: ${SCENARIO}${NC}"
echo -e "${BLUE}[*] Acting user: ${CURRENT_USER}  TTY: ${CURRENT_TTY}${NC}\n"

# ------------------------------ Logs & Backups ------------------------------
STAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/var/log/cyberpatriots_hardening_${STAMP}.log"
BACKUP_DIR="/root/cyberpatriots_backups_${STAMP}"
mkdir -p "${BACKUP_DIR}"
exec > >(tee -a "${LOGFILE}") 2>&1
umask 027
trap 'echo -e "\n${RED}[!] Error on line $LINENO. See ${LOGFILE}.${NC}"' ERR
echo -e "${GREEN}[+] Logging to: ${LOGFILE}${NC}"
echo -e "${GREEN}[+] Backups in: ${BACKUP_DIR}${NC}"

make_backup() {
  local src="$1" dst
  if [[ -e "$src" ]]; then
    dst="${BACKUP_DIR}${src}"
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

# ------------------------------ Scenario: Accounts ------------------------------
# Authorized Administrators (exact per README) with required passwords
declare -A ADMIN_PASS=(
  [twellick]='3Corp3x3cutive'
  [jplofe]='AuditM4n@g3r'
  [pmccleery]='root'
  [wbraddock]='NetworkB0ss'
  [ealderson]='samsep10l'
  [lchong]='t3chn1t!on'
  [sswailem]='data'
)
# Authorized Users (regular)
AUTHORIZED_REG_USERS=(
  pprice sknowles tcolby jchutney sweinsberg sjacobs lspencer mralbern
  jrobinson gsheldern coshearn jlaslen kshelvern jtholdon belkarn bharper
)

# Build lists
ADMINISTRATORS=( "${!ADMIN_PASS[@]}" )
AUTHORIZED_USERS=( "${ADMINISTRATORS[@]}" "${AUTHORIZED_REG_USERS[@]}" )
DEFAULT_USER_PASS='Ecorp#2025!!'   # 12+ chars; letters+digits+specials
AUTO_LOGIN_USER="${CURRENT_USER}"  # safest default in CP images

# Group authorizations (tight + include current competitor for safety)
declare -A GROUPS_AUTHORIZED=(
  ["adm"]="syslog,${CURRENT_USER}"
  ["sudo"]="$(printf '%s ' "${ADMINISTRATORS[@]}")${CURRENT_USER}"
)

# System users to set nologin
declare -A SYSTEM_USERS=(
  [daemon]="/usr/sbin/nologin" [bin]="/usr/sbin/nologin" [sys]="/usr/sbin/nologin"
  [sync]="/bin/sync" [games]="/usr/sbin/nologin" [man]="/usr/sbin/nologin"
  [lp]="/usr/sbin/nologin" [mail]="/usr/sbin/nologin" [news]="/usr/sbin/nologin"
  [uucp]="/usr/sbin/nologin" [proxy]="/usr/sbin/nologin" [www-data]="/usr/sbin/nologin"
  [backup]="/usr/sbin/nologin" [list]="/usr/sbin/nologin" [irc]="/usr/sbin/nologin"
  [gnats]="/usr/sbin/nologin" [nobody]="/usr/sbin/nologin"
)

# Password policy
PASS_MAX_DAYS=90; PASS_MIN_DAYS=7; PASS_WARN_AGE=14; MIN_PASS_LENGTH=12

# Services
svc_exists(){ systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx "${1}.service"; }
svc_active(){ systemctl is-active --quiet "$1"; }
REQUIRED_SERVICES=(ssh)  # sshd is critical
[[ "$SCENARIO" == "web_server" ]] && REQUIRED_SERVICES+=("apache2")

# Services we often disable (never touch CCS/Scoring; never touch LightDM)
ALWAYS_DISABLE=(avahi-daemon cups bluetooth cups-browsed whoopsie speech-dispatcher modemmanager mobile-broadband-provider-info)
SUSPICIOUS_SERVICES=(vsftpd pure-ftpd proftpd nginx lighttpd mysql postgresql smbd nmbd snmpd xinetd inetd rpcbind bind9 dnsmasq slapd nfs-kernel-server telnet)
SERVICE_SKIP_PATTERNS=("ccs" "scoring" "cyberpatriot" "score" "lightdm")  # DO NOT touch these
skip_service(){
  local s="$1"; [[ " ${REQUIRED_SERVICES[*]} " == *" $s "* ]] && return 0
  for p in "${SERVICE_SKIP_PATTERNS[@]}"; do [[ "$s" =~ $p ]] && return 0; done
  return 1
}

# Files to quarantine
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac" "*.mov" "*.wmv" "*.aac" "*.wav" "*.ogg" "*.iso" "*.torrent")

# ------------------------------ Backups ------------------------------
for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/login.defs /etc/security/pwquality.conf \
         /etc/pam.d/common-auth /etc/pam.d/common-password /etc/ssh/sshd_config /etc/sysctl.conf /etc/crontab; do
  make_backup "$f"
done
[[ -d /etc/sudoers.d ]] && { mkdir -p "${BACKUP_DIR}/etc"; tar -C / -czf "${BACKUP_DIR}/etc/sudoers.d.tgz" etc/sudoers.d; }
[[ -d /etc/lightdm   ]] && { mkdir -p "${BACKUP_DIR}/etc"; tar -C / -czf "${BACKUP_DIR}/etc/lightdm.tgz"   etc/lightdm; }
[[ -d /etc/ufw       ]] && { mkdir -p "${BACKUP_DIR}/etc"; tar -C / -czf "${BACKUP_DIR}/etc/ufw.tgz"       etc/ufw; }

# ------------------------------ REVERT helper ------------------------------
cat > "${BACKUP_DIR}/REVERT.sh" <<'EOS'
#!/bin/bash
set -Eeuo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
restore(){ [[ -e "__BD__${1}" ]] && cp -a "__BD__${1}" "${1}"; }
untar(){ [[ -f "__BD__${1}" ]] && tar -C / -xzf "__BD__${1}"; }
restore /etc/passwd; restore /etc/group; restore /etc/shadow; restore /etc/gshadow
restore /etc/login.defs; restore /etc/security/pwquality.conf
restore /etc/pam.d/common-auth; restore /etc/pam.d/common-password
restore /etc/ssh/sshd_config; restore /etc/sysctl.conf; restore /etc/crontab
untar /etc/sudoers.d.tgz; untar /etc/lightdm.tgz; untar /etc/ufw.tgz
visudo -cf /etc/sudoers || echo "WARNING: sudoers syntax check failed"
sysctl -p || true
systemctl enable --now ssh || true
systemctl restart ssh || true
ufw --force disable || true; ufw --force enable || true
CU=$(logname 2>/dev/null || echo "${SUDO_USER:-}")
[[ -n "$CU" ]] && usermod -aG sudo "$CU" || true
echo "Revert complete."
EOS
sed -i "s|__BD__|${BACKUP_DIR}|g" "${BACKUP_DIR}/REVERT.sh"
chmod 700 "${BACKUP_DIR}/REVERT.sh"
echo -e "${GREEN}[+] REVERT helper created: ${BACKUP_DIR}/REVERT.sh${NC}"

# ======================== Helper funcs to prevent spam ========================
in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }
current_shell() { getent passwd "$1" | awk -F: '{print $7}'; }
shadow_hash() { awk -F: -v u="$1" '$1==u{print $2}' /etc/shadow 2>/dev/null; }

set_pass_if_needed() {
  local u="$1" pw="$2"
  [[ "$pw" == "__SKIP__" ]] && return 0
  local want cur
  want="$(openssl passwd -6 "$pw")"
  cur="$(shadow_hash "$u")"
  # Set only if different and not locked
  if [[ -z "$cur" || ( "$cur" != "$want" && "$cur" != '!'* && "$cur" != '*'* ) ]]; then
    usermod -p "$want" "$u"
  fi
}

ensure_shell() {
  local u="$1" sh="${2:-/bin/bash}"
  if [[ "$(current_shell "$u")" != "$sh" ]]; then usermod -s "$sh" "$u"; fi
}

ensure_user() {
  local u="$1" pw="$2" sudo_flag="${3:-no}"
  if id "$u" &>/dev/null; then
    set_pass_if_needed "$u" "$pw"
  else
    adduser --disabled-password --gecos "" "$u"
    [[ "$pw" != "__SKIP__" ]] && usermod -p "$(openssl passwd -6 "$pw")" "$u"
  fi
  ensure_shell "$u" /bin/bash
  if [[ "$sudo_flag" == "yes" ]] && ! in_group "$u" sudo; then usermod -aG sudo "$u"; fi
}

expire_if_needed() {
  local u="$1"
  local lastchg
  lastchg=$(awk -F: -v u="$u" '$1==u{print $3}' /etc/shadow 2>/dev/null)
  if [[ -n "$lastchg" && "$lastchg" -ne 0 ]]; then
    passwd -e "$u" >/dev/null 2>&1 || chage -d 0 "$u" >/dev/null 2>&1 || true
  fi
}

# ==================================================
# PHASE 1: Packages
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          PHASE 1: PACKAGE MANAGEMENT          ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ufw libpam-pwquality auditd audispd-plugins openssl
apt-get install -y openssh-server apache2 chromium gimp inkscape scribus || true
apt-get upgrade -y
apt-get autoremove -y
apt-get autoclean -y

# ==================================================
# PHASE 2: Sudoers safety
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      PHASE 2: SUDOERS SAFETY & CLEANUP        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

RESCUE_FILE="/etc/sudoers.d/99-cp-rescue"
if [[ ! -f "$RESCUE_FILE" ]]; then
  echo "${CURRENT_USER} ALL=(ALL:ALL) ALL" > "$RESCUE_FILE"
  chown root:root "$RESCUE_FILE"; chmod 0440 "$RESCUE_FILE"
fi
visudo -cf /etc/sudoers >/dev/null 2>&1 || { echo -e "${RED}[!] Fix /etc/sudoers then rerun.${NC}"; exit 1; }
cp -a /etc/sudoers "${BACKUP_DIR}/sudoers.pre-nopasswd.bak"
sed -Ei 's/(,?\s*)NOPASSWD:/\1/g' /etc/sudoers
if [[ -d /etc/sudoers.d ]]; then
  for f in /etc/sudoers.d/*; do [[ -f "$f" ]] && sed -Ei 's/(,?\s*)NOPASSWD:/\1/g' "$f"; done
fi
visudo -cf /etc/sudoers >/dev/null 2>&1 || cp -a "${BACKUP_DIR}/sudoers.pre-nopasswd.bak" /etc/sudoers
usermod -aG sudo "${CURRENT_USER}" || true

# ==================================================
# PHASE 3: User management
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            PHASE 3: USER MANAGEMENT           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

# Lock system shells
for u in "${!SYSTEM_USERS[@]}"; do id "$u" &>/dev/null && usermod -s "${SYSTEM_USERS[$u]}" "$u" 2>/dev/null || true; done

# Create admins (respect SKIP_CURRENT_ADMIN_PW_CHANGE for auto-login admin)
for a in "${ADMINISTRATORS[@]}"; do
  pw="${ADMIN_PASS[$a]}"
  if [[ "$SKIP_CURRENT_ADMIN_PW_CHANGE" == "yes" && "$a" == "$AUTO_LOGIN_USER" ]]; then
    pw="__SKIP__"; echo "[*] Skipping password change for current auto-login admin: $a"
  fi
  ensure_user "$a" "$pw" "yes"
done
usermod -aG sudo "${CURRENT_USER}" || true

# Create authorized regular users with strong temp password (expire on next login)
for u in "${AUTHORIZED_REG_USERS[@]}"; do
  if [[ "$u" == "$AUTO_LOGIN_USER" ]]; then
    ensure_user "$u" "__SKIP__" "no"
  else
    ensure_user "$u" "$DEFAULT_USER_PASS" "no"
    expire_if_needed "$u"
  fi
done

# Password aging for all real users
for u in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  chage --maxdays "$PASS_MAX_DAYS" --mindays "$PASS_MIN_DAYS" --warndays "$PASS_WARN_AGE" "$u" 2>/dev/null || true
done

# Secure home directories (use actual primary group)
for d in /home/*; do
  [[ -d "$d" ]] || continue
  u=$(basename "$d")
  if id "$u" &>/dev/null; then
    pg=$(id -gn "$u" 2>/dev/null || echo "$u")
    chmod 750 "$d"
    chown "$u:$pg" "$d" 2>/dev/null || true
  else
    echo -e "${YELLOW}[!] Orphaned home: $d${NC}"
    [[ "$COMPETITION_MODE" == "yes" ]] && rm -rf "$d"
  fi
done

# Remove unauthorized human users
PROTECT_USERS=("root" "${CURRENT_USER}" "${AUTHORIZED_USERS[@]}")
is_protect(){ local x="$1"; for p in "${PROTECT_USERS[@]}"; do [[ "$x" == "$p" ]] && return 0; done; return 1; }
DELETED_USERS=0
for u in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  if ! is_protect "$u"; then
    pkill -u "$u" 2>/dev/null || true
    userdel -r "$u" 2>/dev/null && ((DELETED_USERS++)) || true
    echo -e "${GREEN}[+] Deleted unauthorized user: $u${NC}"
  fi
done

# Exact sudo group membership: only admins + current competitor
echo -e "${YELLOW}[*] Pruning sudo group membership...${NC}"
ALLOW_SUDO=( "${ADMINISTRATORS[@]}" "${CURRENT_USER}" )
CUR_SUDO=$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')
# Remove unexpected members
for u in $CUR_SUDO; do
  keep=false; for a in "${ALLOW_SUDO[@]}"; do [[ "$u" == "$a" ]] && keep=true; done
  $keep || deluser "$u" sudo >/dev/null 2>&1 || true
done
# Ensure required members are present
for u in "${ALLOW_SUDO[@]}"; do
  id "$u" &>/dev/null && ! in_group "$u" sudo && usermod -aG sudo "$u"
done

# ==================================================
# PHASE 4: PAM & password quality
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      PHASE 4: PAM & PASSWORD HARDENING        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

make_backup /etc/login.defs
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${PASS_MAX_DAYS}/" /etc/login.defs || echo "PASS_MAX_DAYS   ${PASS_MAX_DAYS}" >> /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${PASS_MIN_DAYS}/" /etc/login.defs || echo "PASS_MIN_DAYS   ${PASS_MIN_DAYS}" >> /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${PASS_WARN_AGE}/" /etc/login.defs || echo "PASS_WARN_AGE   ${PASS_WARN_AGE}" >> /etc/login.defs
grep -q '^ENCRYPT_METHOD' /etc/login.defs && sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs || echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs
grep -q '^PASS_MIN_LEN' /etc/login.defs || echo "PASS_MIN_LEN   ${MIN_PASS_LENGTH}" >> /etc/login.defs

cat > /etc/security/pwquality.conf << EOF
# CyberPatriot Password Quality
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

make_backup /etc/pam.d/common-auth
make_backup /etc/pam.d/common-password

if grep -q pam_faillock.so /etc/pam.d/common-auth || [[ -f /lib/security/pam_faillock.so || -f /usr/lib/security/pam_faillock.so ]]; then
  sed -i '/pam_tally2.so/d' /etc/pam.d/common-auth || true
  grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth || \
    sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800 fail_interval=900' /etc/pam.d/common-auth
  grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth || \
    sed -i '/^auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800 fail_interval=900' /etc/pam.d/common-auth
else
  grep -q 'pam_tally2.so' /etc/pam.d/common-auth || \
    sed -i '1i auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail' /etc/pam.d/common-auth
fi

grep -q 'pam_pwhistory.so' /etc/pam.d/common-password || \
  sed -i '1i password requisite pam_pwhistory.so remember=5 use_authtok' /etc/pam.d/common-password

command -v faillock >/dev/null 2>&1 && faillock --user "${CURRENT_USER}" --reset || true

# ==================================================
# PHASE 5: Services (keep ssh & apache)
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           PHASE 5: SERVICE MANAGEMENT         ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true
if dpkg -l | grep -q '^ii\s\+apache2'; then systemctl enable --now apache2 2>/dev/null || true; fi

echo -e "${YELLOW}[*] Disabling non-required services...${NC}"
DISABLED_COUNT=0
for s in "${ALWAYS_DISABLE[@]}"; do
  if svc_exists "$s" && ! skip_service "$s"; then
    systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true
    ((DISABLED_COUNT++)); echo -e "${GREEN}[+] Disabled $s${NC}"
  fi
done
for s in "${SUSPICIOUS_SERVICES[@]}"; do
  if svc_exists "$s" && ! skip_service "$s"; then
    systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true
    ((DISABLED_COUNT++)); echo -e "${GREEN}[+] Disabled $s${NC}"
  fi
done
echo -e "${GREEN}[+] Disabled $DISABLED_COUNT services${NC}"

# ==================================================
# PHASE 6: Remove tools/games
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      PHASE 6: REMOVE MALICIOUS SOFTWARE       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

HACKER_TOOLS=(john john-the-ripper hydra hydra-gtk nmap zenmap metasploit metasploit-framework wireshark tshark sqlmap aircrack-ng ophcrack nikto medusa burpsuite ettercap ettercap-text-only kismet netcat nc netcat-traditional netcat-openbsd hashcat rainbowcrack dsniff fcrackzip lcrack crack remmina telnet ftp)
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
# PHASE 7: SSH hardening
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             PHASE 7: SSH HARDENING            ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

SSH_CONFIG='/etc/ssh/sshd_config'
if [[ -f "$SSH_CONFIG" ]]; then
  make_backup "$SSH_CONFIG"
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSH_CONFIG"   # avoid lockouts
  sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
  sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
  sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSH_CONFIG"
  sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' "$SSH_CONFIG"
  sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/' "$SSH_CONFIG"
  sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' "$SSH_CONFIG"
  sed -i 's/^#*StrictModes.*/StrictModes yes/' "$SSH_CONFIG"
  sed -i '/^#*UsePrivilegeSeparation/d' "$SSH_CONFIG"
  sed -i '/^#*Protocol[[:space:]]\+2/d' "$SSH_CONFIG"

  # Allow all authorized admins + regular users (dedup, no mapfile)
  ALLOW_LIST=( "${ADMINISTRATORS[@]}" "${AUTHORIZED_REG_USERS[@]}" )
  ALLOW_UNIQ=()
  for u in "${ALLOW_LIST[@]}"; do
    [[ " ${ALLOW_UNIQ[*]} " == *" $u "* ]] || ALLOW_UNIQ+=("$u")
  done
  if grep -q '^AllowUsers' "$SSH_CONFIG"; then
    sed -i "s#^AllowUsers.*#AllowUsers ${ALLOW_UNIQ[*]}#" "$SSH_CONFIG"
  else
    echo "AllowUsers ${ALLOW_UNIQ[*]}" >> "$SSH_CONFIG"
  fi

  systemctl restart ssh || { echo -e "${RED}[!] ssh restart failed—reverting sshd_config${NC}"; cp -a "${BACKUP_DIR}/etc/ssh/sshd_config" "$SSH_CONFIG"; systemctl restart ssh || true; }
  echo -e "${GREEN}[+] SSH hardened and allows authorized users${NC}"
fi

# ==================================================
# PHASE 8: Firewall (UFW)
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        PHASE 8: FIREWALL CONFIGURATION        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

ufw --force disable || true
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw allow 22/tcp comment 'SSH'
if dpkg -l | grep -q '^ii\s\+apache2'; then
  ufw allow 80/tcp  comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
fi
ufw logging high
ufw --force enable || true

# ==================================================
# PHASE 9: Kernel hardening
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           PHASE 9: KERNEL HARDENING           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

make_backup /etc/sysctl.conf
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
  sed -i '/^net\.ipv6\.conf\..*disable_ipv6/d' /etc/sysctl.conf || true
fi
sysctl -p 2>/dev/null || true

# ==================================================
# PHASE 10: File perms & cleanup
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     PHASE 10: FILE PERMISSIONS & CLEANUP      ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

chmod 644 /etc/passwd; chmod 640 /etc/shadow
chmod 644 /etc/group;  chmod 640 /etc/gshadow
chown root:root /etc/passwd /etc/group /etc/crontab /etc/ssh/sshd_config 2>/dev/null || true
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || true
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

# Conservative SUID removals
for b in /usr/bin/at /usr/bin/lppasswd /usr/bin/newgrp /usr/bin/wall /usr/bin/write /usr/bin/mount /usr/bin/umount; do
  [[ -f "$b" ]] && chmod u-s "$b" 2>/dev/null || true
done

# Safe temp cleanup
find /tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
find /var/tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
find /dev/shm -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true

# ==================================================
# PHASE 11: Media quarantine (per README policy)
# ==================================================
if [[ "$MEDIA_QUARANTINE" == "yes" ]]; then
  echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║           PHASE 11: MEDIA QUARANTINE          ║${NC}"
  echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
  QUAR="${BACKUP_DIR}/quarantine_media"; mkdir -p "$QUAR"
  for loc in /home /root /opt; do
    for pat in "${FILE_TYPES_TO_REMOVE[@]}"; do
      find "$loc" -type f -iname "$pat" -exec mv -t "$QUAR" -- {} + 2>/dev/null || true
    done
  done
  echo -e "${GREEN}[+] Media files quarantined to $QUAR${NC}"
fi

# ==================================================
# PHASE 12: Display manager must remain LightDM
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          PHASE 12: DISPLAY MANAGER (DM)       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

if [[ -f /etc/X11/default-display-manager ]]; then
  CUR_DM="$(cat /etc/X11/default-display-manager 2>/dev/null || true)"
  if [[ "$CUR_DM" != "/usr/sbin/lightdm" ]]; then
    echo -e "${YELLOW}[!] DM is '$CUR_DM'. Setting LightDM per README...${NC}"
    echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections
    dpkg-reconfigure -fnoninteractive lightdm || true
  else
    echo -e "${GREEN}[+] LightDM already set as display manager${NC}"
  fi
fi

# ==================================================
# PHASE 13: Audit & monitoring
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          PHASE 13: AUDIT & MONITORING         ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}=== UID 0 Users ===${NC}"; awk -F: '$3 == 0 {print $1}' /etc/passwd
echo -e "\n${YELLOW}=== Sudoers ===${NC}"; getent group sudo | cut -d: -f4
echo -e "\n${YELLOW}=== Cron directories ===${NC}"; ls /etc/cron.* 2>/dev/null | grep -v '\.placeholder' || true
for u in $(cut -f1 -d: /etc/passwd); do crontab -u "$u" -l 2>/dev/null | grep -Ev '^(#|$)' && echo "User: $u"; done
echo -e "\n${YELLOW}=== Listening services ===${NC}"; ss -tulpn | grep LISTEN || true
systemctl enable --now auditd 2>/dev/null || true

# ==================================================
# FINAL: Validations & banner
# ==================================================
echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               FINAL VALIDATION                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"

if groups "${CURRENT_USER}" | grep -q '\bsudo\b'; then
  echo -e "${GREEN}[✓] ${CURRENT_USER} is in sudo group${NC}"
else
  echo -e "${RED}[!] Restoring sudo group for ${CURRENT_USER}${NC}"; usermod -aG sudo "${CURRENT_USER}" || true
fi
sudo -l -U "${CURRENT_USER}" >/dev/null 2>&1 || echo -e "${YELLOW}[!] Could not validate sudo -U for ${CURRENT_USER}${NC}"

if groups "${CURRENT_USER}" | grep -q '\bsudo\b' && visudo -cf /etc/sudoers >/dev/null 2>&1; then
  rm -f /etc/sudoers.d/99-cp-rescue || true
  echo -e "${GREEN}[+] Removed temporary sudoers rescue file${NC}"
else
  echo -e "${YELLOW}[!] Keeping rescue sudoers file for safety${NC}"
fi

cat > "${BACKUP_DIR}/SCORING_CHECKLIST.txt" << EOF
CYBERPATRIOT SCORING CHECKLIST
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
  - AllowUsers covers admins+users: $(grep -Eiq '^\s*AllowUsers' /etc/ssh/sshd_config && echo YES || echo NO)

Firewall (UFW):
  - Status: $(ufw status | head -n1)
  - Rules:
$(ufw status | sed 's/^/    /')

Kernel Hardening:
  - dmesg_restrict=1, kptr_restrict=2, ptrace_scope=1 set

Services:
  - SSH enabled: $(systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null)
  - Apache enabled (if installed): $(systemctl is-enabled apache2 2>/dev/null || echo "not installed")
  - Disabled count: ${DISABLED_COUNT}

Apps (Mint 21 official):
  - Chromium: $(dpkg -l | awk '/^ii/ && $2=="chromium"{print $3}')
  - GIMP:     $(dpkg -l | awk '/^ii/ && $2=="gimp"{print $3}')
  - Inkscape: $(dpkg -l | awk '/^ii/ && $2=="inkscape"{print $3}')
  - Scribus:  $(dpkg -l | awk '/^ii/ && $2=="scribus"{print $3}')

Backups & Revert:
  - Backups dir: ${BACKUP_DIR}
  - Revert script: ${BACKUP_DIR}/REVERT.sh
EOF

echo -e "\n${GREEN}===============================================${NC}"
echo -e "${GREEN}✅  CyberPatriot Hardening Complete!${NC}"
echo -e "${GREEN}📁 Backups: ${BACKUP_DIR}${NC}"
echo -e "${GREEN}🔁 Revert with: ${BACKUP_DIR}/REVERT.sh${NC}"
echo -e "${GREEN}===============================================${NC}\n"
