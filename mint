#!/bin/bash
# =====================================================================
# CyberPatriot Mint 21 Hardening Script (Competition-Safe) + Auto Updates
# - Tailored to prompt requirements
# - Protects the current admin & LightDM autologin user from lockout
# - Does NOT change the protected administrator's password
# - Adds unattended security updates + daily APT periodic tasks
# =====================================================================

set -euo pipefail

# ------------------------------
# Root check
# ------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root (use sudo)."
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
LOGFILE="/var/log/cp_mint21_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "[+] CyberPatriot Mint 21 hardening start @ $STAMP"

# ------------------------------
# Detect protected users
# ------------------------------
PROTECTED_USER="${SUDO_USER:-$(who am i 2>/dev/null | awk '{print $1}')}"
if [[ -z "${PROTECTED_USER:-}" ]]; then
  PROTECTED_USER="$(id -un)"
fi

# Detect LightDM autologin user (if any)
AUTOLOGIN_USER=""
LIGHTDM_DIR="/etc/lightdm"
if [[ -d "$LIGHTDM_DIR" ]]; then
  while IFS= read -r file; do
    u="$(grep -E '^\s*autologin-user\s*=' "$file" | sed -E 's/.*=\s*//g' | head -n1 || true)"
    if [[ -n "$u" ]]; then AUTOLOGIN_USER="$u"; break; fi
  done < <(find "$LIGHTDM_DIR" -maxdepth 2 -type f -name "*.conf" -o -name "lightdm.conf" 2>/dev/null)
fi

# Build a protected set
declare -A PROTECTED_SET
[[ -n "$PROTECTED_USER"  ]] && PROTECTED_SET["$PROTECTED_USER"]=1
[[ -n "$AUTOLOGIN_USER" ]] && PROTECTED_SET["$AUTOLOGIN_USER"]=1

echo "[*] Protected administrator account: ${PROTECTED_USER:-<none>}"
echo "[*] LightDM autologin user (if set): ${AUTOLOGIN_USER:-<none>}"

# ------------------------------
# Scenario: Authorized accounts
# ------------------------------
declare -A ADMIN_PASS
ADMIN_PASS[twellick]='3Corp3x3cutive'
ADMIN_PASS[jplofe]='AuditM4n@g3r'
ADMIN_PASS[pmccleery]='root'
ADMIN_PASS[wbraddock]='NetworkB0ss'
ADMIN_PASS[ealderson]='samsep10l'
ADMIN_PASS[lchong]='t3chn1t!on'
ADMIN_PASS[sswailem]='data'

AUTHORIZED_ADMINS=(twellick jplofe pmccleery wbraddock ealderson lchong sswailem)

AUTHORIZED_USERS=( \
  pprice sknowles tcolby jchutney sweinsberg sjacobs lspencer mralbern \
  jrobinson gsheldern coshearn jlaslen kshelvern jtholdon belkarn bharper \
)

ALL_AUTHZ=("${AUTHORIZED_ADMINS[@]}" "${AUTHORIZED_USERS[@]}")

# ------------------------------
# Helper functions
# ------------------------------
in_array() {
  local needle="$1"; shift
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

ensure_user() {
  local u="$1" pw="${2:-}" groups="${3:-}" create_shell="/bin/bash"
  if id "$u" &>/dev/null; then
    echo "[=] User '$u' exists."
  else
    echo "[+] Creating user '$u'..."
    useradd -m -s "$create_shell" "$u"
  fi

  # Set password only if provided and not protected
  if [[ -n "$pw" && -z "${PROTECTED_SET[$u]:-}" ]]; then
    echo "${u}:${pw}" | chpasswd
    echo "[+] Set password for '$u' (skipped if protected)."
  else
    if [[ -n "${PROTECTED_SET[$u]:-}" ]]; then
      echo "[*] Skipped password change for PROTECTED user '$u'."
    fi
  fi

  # Ensure groups
  if [[ -n "$groups" ]]; then
    IFS=',' read -r -a gs <<<"$groups"
    for g in "${gs[@]}"; do
      getent group "$g" >/dev/null || groupadd "$g"
      if id -nG "$u" | tr ' ' '\n' | grep -qx "$g"; then
        echo "[=] '$u' already in group '$g'."
      else
        usermod -aG "$g" "$u"
        echo "[+] Added '$u' to group '$g'."
      fi
    done
  fi
}

ensure_not_in_group() {
  local u="$1" g="$2"
  id "$u" &>/dev/null || return 0
  if id -nG "$u" | tr ' ' '\n' | grep -qx "$g"; then
    if [[ -n "${PROTECTED_SET[$u]:-}" ]]; then
      echo "[*] Skip removing PROTECTED user '$u' from '$g'."
    else
      deluser "$u" "$g" && echo "[+] Removed '$u' from group '$g'." || echo "[-] Could not remove '$u' from '$g'."
    fi
  fi
}

lock_user_safe() {
  local u="$1"
  if [[ -n "${PROTECTED_SET[$u]:-}" ]]; then
    echo "[*] Skip locking PROTECTED user '$u'."
  else
    usermod -L "$u" && echo "[+] Locked account '$u' (login disabled)."
  fi
}

# ------------------------------
# Packages required by prompt
# ------------------------------
echo "[*] Refreshing apt and installing required packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y

apt-get install -y \
  chromium-browser gimp inkscape scribus \
  apache2 openssh-server ufw \
  libpam-pwquality

# ------------------------------
# Services required by prompt
# ------------------------------
echo "[*] Enabling critical services (sshd, apache2)..."
systemctl enable --now ssh
systemctl enable --now apache2

# ------------------------------
# UFW firewall
# ------------------------------
echo "[*] Configuring UFW (allow OpenSSH, enable logging)..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw logging on || true
yes | ufw enable

# ------------------------------
# Password policy (does NOT change protected admin password)
# ------------------------------
echo "[*] Enforcing password policy (pwquality + login.defs)..."
PWD_PAM="/etc/pam.d/common-password"
[[ -f "$PWD_PAM" ]] && cp -n "$PWD_PAM" "${PWD_PAM}.bak.$STAMP"

if grep -q "pam_pwquality.so" "$PWD_PAM"; then
  sed -i -E 's#^(password\s+requisite\s+pam_pwquality\.so).*#\1 retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1#' "$PWD_PAM"
else
  echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> "$PWD_PAM"
fi

LOGIN_DEFS="/etc/login.defs"
cp -n "$LOGIN_DEFS" "${LOGIN_DEFS}.bak.$STAMP"
sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$LOGIN_DEFS"
sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' "$LOGIN_DEFS"
sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' "$LOGIN_DEFS"

# ------------------------------
# Account lockout via pam_faillock (skip PROTECTED user)
# ------------------------------
echo "[*] Configuring login lockout with pam_faillock (deny=5 for 30m, SKIP protected user)..."
AUTH_PAM="/etc/pam.d/common-auth"
cp -n "$AUTH_PAM" "${AUTH_PAM}.bak.$STAMP"

if ! grep -q "pam_succeed_if.so.*user = ${PROTECTED_USER}" "$AUTH_PAM"; then
  sed -i "1 i auth [success=1 default=ignore] pam_succeed_if.so user = ${PROTECTED_USER}" "$AUTH_PAM"
fi
if ! grep -q "pam_faillock.so preauth" "$AUTH_PAM"; then
  sed -i "2 i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800" "$AUTH_PAM"
fi
if ! grep -q "pam_faillock.so authfail" "$AUTH_PAM"; then
  sed -i '$ a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' "$AUTH_PAM"
fi

command -v faillock >/dev/null 2>&1 || true

# ------------------------------
# Authorized account enforcement
# ------------------------------
echo "[*] Ensuring authorized administrator accounts..."
for a in "${AUTHORIZED_ADMINS[@]}"; do
  pw="${ADMIN_PASS[$a]:-}"
  ensure_user "$a" "$pw" "sudo"
done

echo "[*] Ensuring authorized non-admin user accounts..."
for u in "${AUTHORIZED_USERS[@]}"; do
  ensure_user "$u" "" ""
  ensure_not_in_group "$u" "sudo"
done

# ------------------------------
# Handle unauthorized human users: lock (non-destructive)
# ------------------------------
echo "[*] Locking unauthorized local users (UID >= 1000), non-protected..."
while IFS=: read -r name _ uid _; do
  if [[ "$uid" -ge 1000 && "$name" != "nobody" ]]; then
    if in_array "$name" "${ALL_AUTHZ[@]}"; then
      echo "[=] Authorized user '$name' kept."
      continue
    fi
    if [[ -n "${PROTECTED_SET[$name]:-}" ]]; then
      echo "[*] '$name' is PROTECTED; leaving untouched."
      continue
    fi
    lock_user_safe "$name"
  fi
done < /etc/passwd

# ------------------------------
# Remove hacking tools (if present)
# ------------------------------
echo "[*] Checking/removing prohibited tools (safe purge if installed)..."
TOOLS=(john hydra nmap zenmap metasploit-framework wireshark sqlmap aircrack-ng ophcrack)
for t in "${TOOLS[@]}"; do
  if dpkg -l | awk '{print $2}' | grep -qx "$t"; then
    apt-get -y purge "$t" || true
    echo "[+] Purged '$t'."
  else
    echo "[=] '$t' not installed."
  fi
done
apt-get -y autoremove || true

# ------------------------------
# Ensure LightDM stays default (do not switch DM)
# ------------------------------
echo "[*] Verifying LightDM is present (not altering DM selection)..."
if ! dpkg -l | awk '{print $2}' | grep -qx lightdm; then
  apt-get install -y lightdm
fi
# Do NOT run dpkg-reconfigure; leave current DM as-is.

# ------------------------------
# Ensure SSH stays enabled and available
# ------------------------------
echo "[*] Ensuring SSH stays enabled..."
systemctl enable --now ssh

# ------------------------------
# Media files (interactive removal; safe)
# ------------------------------
echo "[*] Optional: prompt-delete non-work media under /home and /root."
MEDIA_PATTERNS=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")
for pat in "${MEDIA_PATTERNS[@]}"; do
  while IFS= read -r f; do
    echo "[?] Delete '$f'? (y/N)"
    read -r ans
    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then rm -f -- "$f"; echo "[+] Deleted '$f'."; fi
  done < <(find /home /root -type f -iname "$pat" 2>/dev/null || true)
done

# ------------------------------
# Automatic security updates (NEW)
# ------------------------------
echo "[*] Enabling unattended security updates + daily APT periodic tasks..."
apt-get install -y unattended-upgrades apt-listchanges || true

# Back up any existing APT periodic configs
for f in /etc/apt/apt.conf.d/10periodic /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades; do
  [[ -f "$f" ]] && cp -n "$f" "${f}.bak.$STAMP"
done

# Ensure periodic tasks run daily
cat > /etc/apt/apt.conf.d/10periodic <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Ensure unattended-upgrades is enabled
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Minimal unattended-upgrades tuning (auto security upgrades; optional reboot window)
# Note: We don't force reboots; uncomment if desired for your image.
if [[ ! -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
  dpkg-reconfigure -fnoninteractive unattended-upgrades || true
fi
# Ensure no interactive prompts block future runs
sed -i -E 's#^//\s*Unattended-Upgrade::Remove-Unused-Kernel-Packages.*#Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";#' /etc/apt/apt.conf.d/50unattended-upgrades || true
sed -i -E 's#^//\s*Unattended-Upgrade::Remove-Unused-Dependencies.*#Unattended-Upgrade::Remove-Unused-Dependencies "true";#' /etc/apt/apt.conf.d/50unattended-upgrades || true
# Optional controlled reboot time (commented to stay competition-safe)
# echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
# echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades

systemctl enable --now unattended-upgrades.service || true
echo "[+] Unattended-upgrades enabled and scheduled."

# ------------------------------
# Scoring/competition safety reminders
# ------------------------------
echo "[*] Leaving CCS Client & scoring artifacts untouched."
echo "[*] Not altering time zone/date/time."
echo "[*] Not changing display manager configuration beyond verifying LightDM availability."

# ------------------------------
# Create a minimal rollback helper (restores PAM, login.defs, APT configs)
# ------------------------------
ROLLBACK="/root/restore_cp_backups.sh"
cat > "$ROLLBACK" <<EOF
#!/bin/bash
set -e
echo "[*] Restoring PAM, login.defs, and APT config backups where available..."
for f in /etc/pam.d/common-auth /etc/pam.d/common-password /etc/login.defs \
         /etc/apt/apt.conf.d/10periodic /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades; do
  b=\${f}.bak.$STAMP
  if [[ -f "\$b" ]]; then
    cp -f "\$b" "\$f"
    echo "[+] Restored \$f from \$b"
  fi
done
echo "[*] To clear lockouts for a user: faillock --user <username> --reset"
echo "[*] Done."
EOF
chmod +x "$ROLLBACK"
echo "[+] Rollback helper created: $ROLLBACK"

echo "[+] Completed CyberPatriot Mint 21 hardening safely (with auto updates)."
echo "[i] Protected admin: ${PROTECTED_USER:-<none>} (password unchanged, no lockout)."
[[ -n "$AUTOLOGIN_USER" ]] && echo "[i] LightDM autologin user '${AUTOLOGIN_USER}' protected as well."
exit 0
