#!/bin/bash
# ==================================================
# Security Hardening + User Management Script (Linux Mint 21)
# CyberPatriot-style scenario (AFA DMZ web + mail audit)
#
# Key policy requirements from prompt:
# - OS: Mint 21 only (use official stable Mint repos)
# - Display manager must remain LightDM (do NOT switch)
# - Default browser must be latest stable Chromium
# - Firewall must be UFW
# - Never let users log in as root (use sudo)
# - WordPress site must remain accessible at http://localhost (Apache + MySQL + PHP)
# - SSH remote login must remain available (sshd enabled)
# - Critical services must remain enabled: sshd, apache2, mysql
# - Do NOT disable/remove CCS Client / scoring
# - Do NOT change timezone/date/time (image is UTC)
# - Do NOT remove authorized users or their home directories
# ==================================================

set -euo pipefail

# ------------------------------
# Ensure run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "[-] Run with sudo/root."
  exit 1
fi

echo "[+] Starting Security Hardening for Linux Mint 21..."

# ------------------------------
# Logging
# ------------------------------
LOGFILE="/var/log/security_hardening_mint21.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------
# Authorized accounts (from prompt)
# ------------------------------
AUTHORIZED_ADMINISTRATORS=(
  "benjamin"
  "rzane2"
  "hspecter"
  "llitt"
  "mross"
)

AUTHORIZED_USERS=(
  "awilliams"
  "swheeler"
  "kbennett"
  "pporter"
  "baltman"
  "rzane"
  "scarter"
  "dpaulson"
  "gbodinski"
)

ALL_AUTHORIZED_USERS=("${AUTHORIZED_ADMINISTRATORS[@]}" "${AUTHORIZED_USERS[@]}")

# ------------------------------
# Config
# ------------------------------
MIN_PASS_LENGTH=12
PASS_MAX_DAYS=90
PASS_MIN_DAYS=10
PASS_WARN_AGE=7

# Remove common “hacking tools”
HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack" "netcat" "netcat-openbsd" "netcat-traditional")

# Media file patterns (prompt says non-work media is prohibited)
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac" "*.mov" "*.wav")

SSH_CONFIG="/etc/ssh/sshd_config"

# If you want the script to actually reset passwords, keep this true.
# (Competition guideline: you are NOT required to change the password of the primary auto-login user.)
RESET_PASSWORDS=true
TEMP_PASSWORD_PREFIX="AFA-Temp!"

# ------------------------------
# Helpers
# ------------------------------
has_user() { id "$1" &>/dev/null; }

detect_autologin_user() {
  # LightDM autologin is commonly configured here on Mint:
  # /etc/lightdm/lightdm.conf or /etc/lightdm/lightdm.conf.d/*.conf
  local u=""
  if [[ -f /etc/lightdm/lightdm.conf ]]; then
    u="$(grep -E '^\s*autologin-user\s*=' /etc/lightdm/lightdm.conf | tail -n1 | cut -d= -f2 | xargs || true)"
  fi
  if [[ -z "$u" ]] && [[ -d /etc/lightdm/lightdm.conf.d ]]; then
    u="$(grep -R -E '^\s*autologin-user\s*=' /etc/lightdm/lightdm.conf.d 2>/dev/null | tail -n1 | cut -d= -f2 | xargs || true)"
  fi
  echo "$u"
}

# ------------------------------
# APT hygiene (Mint 21 official repos)
# ------------------------------
echo "[*] Updating package lists..."
apt-get update -y

# ------------------------------
# User management: list + optional delete unauthorized users (PROMPTED)
# ------------------------------
echo "[*] Checking for unauthorized human users (UID >= 1000)..."
for user in $(awk -F: '{print $1}' /etc/passwd); do
  uid="$(id -u "$user" 2>/dev/null || true)"
  [[ -z "$uid" ]] && continue

  # Skip system accounts, nobody, and typical system service users
  if [[ "$uid" -ge 1000 && "$user" != "nobody" ]]; then
    if [[ ! " ${ALL_AUTHORIZED_USERS[*]} " =~ " ${user} " ]]; then
      echo "[!] Found unauthorized user: $user"
      read -r -p "Delete user '$user' and their home directory? (y/n): " confirm
      if [[ "$confirm" == "y" ]]; then
        echo "[*] Deleting $user..."
        userdel -r "$user" || echo "[-] Failed to delete $user (may be in use)."
      else
        echo "[*] Skipping deletion of $user."
      fi
    fi
  fi
done

# ------------------------------
# Sudo group: keep only authorized admins
# ------------------------------
echo "[*] Enforcing sudo group membership..."
current_sudo_members="$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')"
for u in $current_sudo_members; do
  [[ -z "$u" ]] && continue
  if [[ " ${AUTHORIZED_ADMINISTRATORS[*]} " =~ " ${u} " ]]; then
    echo "[+] Keeping sudo for: $u"
  else
    echo "[!] Removing sudo from: $u"
    deluser "$u" sudo || true
  fi
done

for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
  if has_user "$admin"; then
    usermod -aG sudo "$admin" || true
    echo "[+] Ensured sudo for admin: $admin"
  else
    echo "[!] Authorized admin not found on system: $admin"
  fi
done

# ------------------------------
# Root login policy: disable root password + block root SSH
# ------------------------------
echo "[*] Disabling direct root logins..."
passwd -l root || true

if [[ -f "$SSH_CONFIG" ]]; then
  cp "$SSH_CONFIG" "$SSH_CONFIG.bak.$(date -u +%Y%m%dT%H%M%SZ)" || true

  # Ensure SSH stays usable for authorized users:
  # - PermitRootLogin no
  # - PasswordAuthentication yes (unless you’re using keys already)
  # - UsePAM yes
  sed -i 's/^\s*#\?\s*PermitRootLogin\s\+.*/PermitRootLogin no/' "$SSH_CONFIG" || true
  if ! grep -qE '^\s*PermitRootLogin\s+no\s*$' "$SSH_CONFIG"; then
    echo "PermitRootLogin no" >> "$SSH_CONFIG"
  fi

  sed -i 's/^\s*#\?\s*PasswordAuthentication\s\+.*/PasswordAuthentication yes/' "$SSH_CONFIG" || true
  if ! grep -qE '^\s*PasswordAuthentication\s+yes\s*$' "$SSH_CONFIG"; then
    echo "PasswordAuthentication yes" >> "$SSH_CONFIG"
  fi

  sed -i 's/^\s*#\?\s*UsePAM\s\+.*/UsePAM yes/' "$SSH_CONFIG" || true
  if ! grep -qE '^\s*UsePAM\s+yes\s*$' "$SSH_CONFIG"; then
    echo "UsePAM yes" >> "$SSH_CONFIG"
  fi
else
  echo "[-] SSH config not found: $SSH_CONFIG"
fi

# ------------------------------
# Password policy (pwquality + login.defs)
# ------------------------------
echo "[*] Enforcing password complexity policies..."
apt-get install -y libpam-pwquality

# Set pwquality in /etc/security/pwquality.conf
PWQ="/etc/security/pwquality.conf"
cp "$PWQ" "$PWQ.bak.$(date -u +%Y%m%dT%H%M%SZ)" || true

# Helper: set key=value in pwquality.conf
set_pwq() {
  local key="$1" val="$2"
  if grep -qE "^\s*${key}\s*=" "$PWQ"; then
    sed -i "s/^\s*${key}\s*=.*/${key} = ${val}/" "$PWQ"
  else
    echo "${key} = ${val}" >> "$PWQ"
  fi
}

set_pwq "minlen" "$MIN_PASS_LENGTH"
set_pwq "ucredit" "-1"
set_pwq "lcredit" "-1"
set_pwq "dcredit" "-1"
set_pwq "ocredit" "-1"

# Password aging in /etc/login.defs
echo "[*] Setting password aging..."
cp /etc/login.defs /etc/login.defs.bak.$(date -u +%Y%m%dT%H%M%SZ) || true
sed -i -E "s/^(PASS_MAX_DAYS\s+).*/\1$PASS_MAX_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_DAYS\s+).*/\1$PASS_MIN_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_WARN_AGE\s+).*/\1$PASS_WARN_AGE/" /etc/login.defs

# ------------------------------
# Account lockout (pam_faillock)
# ------------------------------
echo "[*] Configuring login failure lockout..."
apt-get install -y libpam-modules

COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"

cp "$COMMON_AUTH" "$COMMON_AUTH.bak.$(date -u +%Y%m%dT%H%M%SZ)" || true
cp "$COMMON_ACCOUNT" "$COMMON_ACCOUNT.bak.$(date -u +%Y%m%dT%H%M%SZ)" || true

# Insert faillock lines only if missing.
if ! grep -q "pam_faillock.so.*preauth" "$COMMON_AUTH"; then
  sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' "$COMMON_AUTH"
fi
if ! grep -q "pam_faillock.so.*authfail" "$COMMON_AUTH"; then
  echo "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800" >> "$COMMON_AUTH"
fi
if ! grep -q "pam_faillock.so" "$COMMON_ACCOUNT"; then
  echo "account required pam_faillock.so" >> "$COMMON_ACCOUNT"
fi

# ------------------------------
# Firewall (UFW) — allow SSH + web
# ------------------------------
echo "[*] Configuring UFW..."
apt-get install -y ufw

ufw default deny incoming
ufw default allow outgoing

# SSH must remain available (port 22 per prompt; do not change)
ufw allow 22/tcp

# WordPress via Apache locally; also typically allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

ufw logging on
ufw --force enable

# ------------------------------
# Ensure Chromium is installed + set default browser
# ------------------------------
echo "[*] Ensuring Chromium is installed and set as default..."
apt-get install -y chromium || true

# Mint usually uses /usr/bin/chromium; some systems use chromium-browser
if command -v chromium >/dev/null 2>&1; then
  update-alternatives --install /usr/bin/x-www-browser x-www-browser "$(command -v chromium)" 100 || true
  update-alternatives --set x-www-browser "$(command -v chromium)" || true
elif command -v chromium-browser >/dev/null 2>&1; then
  update-alternatives --install /usr/bin/x-www-browser x-www-browser "$(command -v chromium-browser)" 100 || true
  update-alternatives --set x-www-browser "$(command -v chromium-browser)" || true
else
  echo "[-] Chromium not found after install attempt. Check Mint repos / package manager."
fi

# ------------------------------
# Remove hacking tools
# ------------------------------
echo "[*] Removing prohibited tools..."
for tool in "${HACKER_TOOLS[@]}"; do
  if dpkg -l | awk '{print $2}' | grep -qx "$tool"; then
    echo "[!] Purging $tool..."
    apt-get remove --purge -y "$tool" || true
  else
    echo "[+] Not installed: $tool"
  fi
done
apt-get autoremove -y || true

# ------------------------------
# Remove non-work media files (PROMPTED)
# ------------------------------
echo "[*] Searching for non-work media files..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
  find /home /root -type f -iname "$pattern" 2>/dev/null | while read -r f; do
    echo "[!] Found media: $f"
    read -r -p "Delete '$f'? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
      rm -f "$f" && echo "[+] Deleted."
    else
      echo "[*] Kept."
    fi
  done
done

# ------------------------------
# Password resets (skip autologin user)
# ------------------------------
AUTOLOGIN_USER="$(detect_autologin_user || true)"
if [[ -n "$AUTOLOGIN_USER" ]]; then
  echo "[*] Detected LightDM autologin user: $AUTOLOGIN_USER (will skip password reset for safety)"
else
  echo "[*] No LightDM autologin user detected (or config not found)."
fi

if [[ "$RESET_PASSWORDS" == "true" ]]; then
  echo "[*] Resetting passwords for human accounts (except autologin user)..."
  for u in "${ALL_AUTHORIZED_USERS[@]}"; do
    if has_user "$u"; then
      if [[ -n "$AUTOLOGIN_USER" && "$u" == "$AUTOLOGIN_USER" ]]; then
        echo "[*] Skipping autologin account password reset: $u"
        continue
      fi

      # Temp password pattern (edit if you want a different scheme)
      # Example: AFA-Temp!<username>!2025
      TEMP_PASS="${TEMP_PASSWORD_PREFIX}${u}!2025"

      echo "[*] Setting temp password for $u and forcing change at next login..."
      echo "${u}:${TEMP_PASS}" | chpasswd
      chage -d 0 "$u" || true
      echo "[+] $u updated (temp password set; must change at next login)."
    else
      echo "[!] Authorized user missing on system: $u"
    fi
  done
else
  echo "[*] RESET_PASSWORDS=false; skipping password reset stage."
fi

# ------------------------------
# Ensure critical services remain enabled (do NOT disable!)
# ------------------------------
echo "[*] Ensuring critical services are enabled and running..."

# SSH
systemctl enable --now ssh || systemctl enable --now sshd || true

# Apache
systemctl enable --now apache2 || true

# MySQL (service name can be mysql on Mint/Ubuntu)
systemctl enable --now mysql || true

# Restart SSH if config changed
systemctl restart ssh || systemctl restart sshd || true

# ------------------------------
# Optional: disable common conflicting web server (nginx) if installed
# (Does NOT touch apache2)
# ------------------------------
if systemctl list-unit-files | grep -qw nginx.service; then
  if systemctl is-enabled --quiet nginx; then
    echo "[*] Disabling nginx to avoid conflict with Apache..."
    systemctl disable --now nginx || true
  fi
fi

# ------------------------------
# Notes / reminders
# ------------------------------
echo "[*] Reminder: Display manager should remain LightDM (script does not change it)."
echo "[*] Reminder: Do NOT change timezone/date/time (script does not touch it)."
echo "[*] Reminder: Do NOT remove/stop CCS Client/scoring (script does not target it)."
echo "[+] Completed hardening steps for Linux Mint 21."
exit 0
