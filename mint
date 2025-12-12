#!/bin/bash
# ==================================================
# Security Hardening + User Management for Ubuntu 24.04 (CyberPatriot-style)
# Scenario-aligned for AFA DMZ web/mail audit:
# - Keep GDM3
# - Default browser: Google Chrome (stable)
# - Firewall: UFW (allow 80 after reverse shell removed)
# - Critical services must remain available: nginx, mysql
# - Enable nginx logging to default location
# ==================================================

set -euo pipefail

# ------------------------------
# Ensure the script is run as root via sudo
# ------------------------------
if [[ ${EUID:-999} -ne 0 ]]; then
  echo "[-] Run with sudo (do not log in as root)."
  exit 1
fi

# Track the invoking user so we don't delete the active account by accident.
INVOKING_USER="${SUDO_USER:-}"

echo "[+] Starting Security Hardening and User Management Script for Ubuntu 24.04..."

# ------------------------------
# Logging Configuration
# ------------------------------
LOGFILE="/var/log/security_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------
# Configuration Variables (SCENARIO)
# ------------------------------

# Authorized Administrators (must have sudo privileges)
AUTHORIZED_ADMINISTRATORS=(
  "benjamin"
  "rzane2"
  "hspecter"
  "llitt"
  "mross"
)

# Authorized Non-Admin Users
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

# Password Policy
MIN_PASS_LENGTH=12
PASSWORD_COMPLEXITY="ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
PASS_MAX_DAYS=90
PASS_MIN_DAYS=10
PASS_WARN_AGE=7

COMMON_PASSWORD="/etc/pam.d/common-password"
COMMON_AUTH="/etc/pam.d/common-auth"
LOGIN_DEFS="/etc/login.defs"

# Media + "hacking tools" (prompted removals)
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")
HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack")

# Keep this conservative; removing random desktop apps on a server image can be noisy.
UNNECESSARY_PACKAGES=("telnet" "ftp" "rsh-server" "rsh-client")

# Web stack basics
NGINX_CONF="/etc/nginx/nginx.conf"
NGINX_DEFAULT_ACCESS="/var/log/nginx/access.log"
NGINX_DEFAULT_ERROR="/var/log/nginx/error.log"

# ------------------------------
# SAFETY NOTES (Scenario)
# - Do NOT disable nginx/mysql (wiki must stay up)
# - Do NOT remove CCS Client or scoring components
# - Do NOT change timezone/time/date
# - Do NOT delete authorized users or their home dirs
# - Avoid touching the auto-login user password (not required)
# ------------------------------

# ------------------------------
# Helper: check membership in authorized list
# ------------------------------
is_authorized_user() {
  local u="$1"
  for a in "${ALL_AUTHORIZED_USERS[@]}"; do
    [[ "$u" == "$a" ]] && return 0
  done
  return 1
}

# ------------------------------
# User Management
# ------------------------------
echo "[*] Managing users..."

echo "[*] Checking for unauthorized human users (UID >= 1000)..."
while IFS=: read -r user _ uid _ _ home _; do
  # Skip non-human/system and nobody
  [[ "$uid" -lt 1000 ]] && continue
  [[ "$user" == "nobody" ]] && continue

  # Never delete the account that invoked sudo (common in CP images)
  if [[ -n "$INVOKING_USER" && "$user" == "$INVOKING_USER" ]]; then
    echo "[+] Skipping invoking user: $user"
    continue
  fi

  if is_authorized_user "$user"; then
    echo "[+] Authorized user present: $user"
  else
    echo "[!] Found UNAUTHORIZED user: $user (home: $home)"
    read -r -p "Delete user '$user' and remove home? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
      userdel -r "$user" && echo "[+] Deleted '$user'." || echo "[-] Failed to delete '$user'."
    else
      echo "[*] Skipped deletion of '$user'."
    fi
  fi
done < /etc/passwd

# ------------------------------
# Administrator Privileges
# ------------------------------
echo "[*] Configuring sudo privileges..."

# Remove unauthorized users from sudo group
echo "[*] Removing unauthorized users from sudo group..."
sudo_members="$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')"
for u in $sudo_members; do
  [[ -z "$u" ]] && continue
  if [[ " ${AUTHORIZED_ADMINISTRATORS[*]} " == *" ${u} "* ]]; then
    echo "[+] Retaining sudo for: $u"
  else
    # Do not remove sudo from invoking user automatically; it may be needed to keep access.
    if [[ -n "$INVOKING_USER" && "$u" == "$INVOKING_USER" ]]; then
      echo "[!] '$u' is invoking user; skipping sudo removal to avoid lockout."
      continue
    fi
    echo "[!] Removing sudo from: $u"
    deluser "$u" sudo || echo "[-] Could not remove '$u' from sudo."
  fi
done

# Add authorized administrators to sudo group
echo "[*] Adding authorized administrators to sudo..."
for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
  if id "$admin" &>/dev/null; then
    usermod -aG sudo "$admin" && echo "[+] Added '$admin' to sudo."
  else
    echo "[-] Admin '$admin' not found on system."
  fi
done

# ------------------------------
# Password Policy Enforcement
# ------------------------------
echo "[*] Enforcing password policies..."

apt-get update -y

echo "[*] Ensuring libpam-pwquality is installed..."
apt-get install -y libpam-pwquality

if [[ -f "$COMMON_PASSWORD" ]]; then
  cp -a "$COMMON_PASSWORD" "${COMMON_PASSWORD}.bak.$(date +%s)"

  # Ensure pam_pwquality line exists and is configured.
  # Ubuntu typically has: "password requisite pam_pwquality.so retry=3"
  if grep -qE 'pam_pwquality\.so' "$COMMON_PASSWORD"; then
    sed -i -E \
      "s/(pam_pwquality\.so.*retry=)[0-9]+/\13/; s/(pam_pwquality\.so.*)/\1 minlen=${MIN_PASS_LENGTH} difok=3 ${PASSWORD_COMPLEXITY}/" \
      "$COMMON_PASSWORD"
  else
    echo "password requisite pam_pwquality.so retry=3 minlen=${MIN_PASS_LENGTH} difok=3 ${PASSWORD_COMPLEXITY}" >> "$COMMON_PASSWORD"
  fi

  # Add remember=5 to pam_unix if present
  if grep -qE 'pam_unix\.so' "$COMMON_PASSWORD"; then
    sed -i -E "s/(pam_unix\.so.*)/\1 remember=5/" "$COMMON_PASSWORD"
  fi

  echo "[+] Updated $COMMON_PASSWORD"
else
  echo "[-] Missing $COMMON_PASSWORD"
fi

echo "[*] Configuring password aging in $LOGIN_DEFS..."
if [[ -f "$LOGIN_DEFS" ]]; then
  cp -a "$LOGIN_DEFS" "${LOGIN_DEFS}.bak.$(date +%s)"
  sed -i -E "s/^(PASS_MAX_DAYS\s+).*/\1${PASS_MAX_DAYS}/" "$LOGIN_DEFS"
  sed -i -E "s/^(PASS_MIN_DAYS\s+).*/\1${PASS_MIN_DAYS}/" "$LOGIN_DEFS"
  sed -i -E "s/^(PASS_WARN_AGE\s+).*/\1${PASS_WARN_AGE}/" "$LOGIN_DEFS"
  echo "[+] Updated $LOGIN_DEFS"
fi

# ------------------------------
# Account Lockout (Ubuntu 24.04 uses pam_faillock)
# ------------------------------
echo "[*] Configuring account lockout with pam_faillock..."
apt-get install -y libpam-modules

if [[ -f "$COMMON_AUTH" ]]; then
  cp -a "$COMMON_AUTH" "${COMMON_AUTH}.bak.$(date +%s)"

  # Insert faillock preauth/authfail if not present
  if ! grep -q "pam_faillock.so" "$COMMON_AUTH"; then
    # Add near top for good coverage
    sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' "$COMMON_AUTH"
    # Add after "pam_unix.so" auth line if present; otherwise append
    if grep -qE '^auth\s+\[success=1 default=ignore\]\s+pam_unix\.so' "$COMMON_AUTH"; then
      sed -i '/^auth\s\+\[success=1 default=ignore\]\s\+pam_unix\.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' "$COMMON_AUTH"
    else
      echo "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800" >> "$COMMON_AUTH"
    fi
    echo "account required pam_faillock.so" >> "$COMMON_AUTH"
  fi

  echo "[+] pam_faillock configured in $COMMON_AUTH"
fi

# ------------------------------
# Ensure root login is disabled (policy: never let users log in as root)
# ------------------------------
echo "[*] Disabling direct root login (locking root password)..."
passwd -l root || true

# ------------------------------
# Display Manager: keep GDM3
# ------------------------------
echo "[*] Ensuring display manager is GDM3 (if applicable)..."
if dpkg -l | grep -qw gdm3; then
  echo "/usr/sbin/gdm3" > /etc/X11/default-display-manager 2>/dev/null || true
  systemctl enable --now gdm3 >/dev/null 2>&1 || true
  echo "[+] GDM3 set/kept."
else
  echo "[*] gdm3 not installed (server image may not use a display manager)."
fi

# ------------------------------
# Firewall Configuration (UFW)
# ------------------------------
echo "[*] Configuring UFW..."
apt-get install -y ufw

ufw --force enable
ufw logging on

# IMPORTANT: Scenario requires allowing port 80 AFTER reverse shell removed.
echo "[!] Reminder: Remove the malicious PHP reverse shell first."
read -r -p "Have you removed the reverse shell and verified the site is clean? (y/n): " cleaned
if [[ "$cleaned" == "y" ]]; then
  ufw allow 80/tcp
  echo "[+] Allowed inbound HTTP (80/tcp)."
else
  echo "[*] Skipping HTTP allow rule for now."
fi

# ------------------------------
# Nginx Logging (default location) + Ensure critical services running
# ------------------------------
echo "[*] Ensuring nginx & mysql are installed and running..."
apt-get install -y nginx mysql-server php-fpm php-mysql

systemctl enable --now mysql || true
systemctl enable --now nginx || true

echo "[*] Enabling nginx access/error logs in default location..."
if [[ -f "$NGINX_CONF" ]]; then
  cp -a "$NGINX_CONF" "${NGINX_CONF}.bak.$(date +%s)"

  # If access_log is explicitly off, remove/override it.
  if grep -qE '^\s*access_log\s+off;' "$NGINX_CONF"; then
    sed -i -E 's/^\s*access_log\s+off;/# access_log off;/' "$NGINX_CONF"
  fi

  # Ensure http{} block contains default access_log/error_log directives.
  # If missing, inject near start of http{ ... }.
  if ! grep -qE '^\s*access_log\s+/var/log/nginx/access\.log' "$NGINX_CONF"; then
    sed -i -E "0,/http\s*{/s//http {\n    access_log ${NGINX_DEFAULT_ACCESS};/" "$NGINX_CONF"
  fi
  if ! grep -qE '^\s*error_log\s+/var/log/nginx/error\.log' "$NGINX_CONF"; then
    sed -i -E "0,/http\s*{/s//http {\n    error_log ${NGINX_DEFAULT_ERROR};/" "$NGINX_CONF"
  fi

  nginx -t && systemctl reload nginx
  echo "[+] nginx logging enabled (default files) + reloaded."
else
  echo "[-] nginx.conf not found at $NGINX_CONF"
fi

# ------------------------------
# Automatic Updates
# ------------------------------
echo "[*] Setting up unattended upgrades..."
apt-get install -y unattended-upgrades
cat >/etc/apt/apt.conf.d/10periodic <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Keep reboot policy conservative for competition images (auto reboot can be disruptive).
cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# ------------------------------
# Install Google Chrome (stable) + set default browser
# ------------------------------
echo "[*] Ensuring Google Chrome stable is installed and default..."
if ! dpkg -l | grep -qw google-chrome-stable; then
  apt-get install -y wget ca-certificates gnupg

  install -d -m 0755 /etc/apt/keyrings
  wget -qO- https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg
  chmod a+r /etc/apt/keyrings/google-chrome.gpg

  cat >/etc/apt/sources.list.d/google-chrome.list <<'EOF'
deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main
EOF

  apt-get update -y
  apt-get install -y google-chrome-stable
fi

update-alternatives --set x-www-browser /usr/bin/google-chrome-stable >/dev/null 2>&1 || true
echo "[+] Chrome installed and set as default (where alternatives apply)."

# ------------------------------
# Remove prohibited tools (promptless, but safe: only if installed)
# ------------------------------
echo "[*] Removing prohibited hacking tools (if installed)..."
for tool in "${HACKER_TOOLS[@]}"; do
  if dpkg -l | grep -qw "$tool"; then
    echo "[!] Purging $tool..."
    apt-get remove --purge -y "$tool" || true
  fi
done

echo "[*] Removing a small set of unnecessary packages (if installed)..."
for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
  if dpkg -l | grep -qw "$pkg"; then
    apt-get remove --purge -y "$pkg" || true
  fi
done

apt-get autoremove -y || true

# ------------------------------
# Media file scan (PROMPT before delete)
# ------------------------------
echo "[*] Scanning for non-work media files (prompted deletes)..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
  find /home /root -type f -iname "$pattern" 2>/dev/null | while read -r file; do
    echo "[!] Found: $file"
    read -r -p "Delete this file? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
      rm -f "$file" && echo "[+] Deleted: $file" || echo "[-] Failed: $file"
    fi
  done
done

# ------------------------------
# Reverse shell triage helper (does NOT auto-delete)
# ------------------------------
echo "[*] Quick PHP webroot triage (no auto-deletes)..."
WEBROOT_CANDIDATES=("/var/www" "/srv/www" "/usr/share/nginx/html")
for root in "${WEBROOT_CANDIDATES[@]}"; do
  if [[ -d "$root" ]]; then
    echo "[*] Searching $root for common reverse-shell indicators..."
    grep -RIn --color=never -E 'fsockopen\(|pfsockopen\(|shell_exec\(|system\(|passthru\(|exec\(|base64_decode\(|eval\(|/bin/bash|/bin/sh|nc -e|bash -i' \
      "$root" 2>/dev/null | head -n 200 || true
  fi
done
echo "[!] If you identify the malicious PHP reverse shell, remove it manually, then re-run this script and answer 'y' when prompted to allow port 80."

echo "[+] Completed hardening steps for Ubuntu 24.04 scenario."
exit 0
