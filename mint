#!/bin/bash

# ==================================================
# Comprehensive Security Hardening and User Management Script for Ubuntu 22.04
# Based on CyberPatriot Ubuntu 22.04 Scenario Requirements
# ==================================================
# This script performs the following tasks:
# - Removes unauthorized users (with confirmation).
# - Assigns administrators to the sudo group.
# - Removes unauthorized users from the sudo group.
# - Enforces password policies and password aging.
# - Configures the UFW firewall.
# - Sets up automatic updates and unattended upgrades.
# - Enables account lockout after multiple failed login attempts.
# - Removes unnecessary packages and hacking tools.
# - Disables unnecessary services.
# - Ensures Google Chrome is installed and set as default browser.
# - Ensures Squid proxy server is installed and configured securely.
# ==================================================

# ------------------------------
# Ensure the script is run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Use sudo."
   exit 1
fi

echo "[+] Starting Security Hardening and User Management Script for Ubuntu 22.04..."

# ------------------------------
# Logging Configuration
# ------------------------------
LOGFILE="/var/log/security_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------
# Configuration Variables
# ------------------------------

# Authorized Administrators (must have sudo privileges)
AUTHORIZED_ADMINISTRATORS=(
    "ealderson"
    "ggoddard"
    "lchong"
    "oparker"
)

# Authorized Non-Admin Users
AUTHORIZED_USERS=(
    "cmoss"
    "twellick"
    "pprice"
    "hdavis"
    "sswailem"
    "anayar"
    "tcolby"
    "dalderson"
)

# Combine all authorized users (admins + non-admin)
ALL_AUTHORIZED_USERS=("${AUTHORIZED_ADMINISTRATORS[@]}" "${AUTHORIZED_USERS[@]}")

# Password Policy Configuration
MIN_PASS_LENGTH=12
PASSWORD_COMPLEXITY="ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"

# Password Expiration Settings
PASS_MAX_DAYS=90
PASS_MIN_DAYS=10
PASS_WARN_AGE=7

# Password Strength Configuration
PASSWORD_STRENGTH='/etc/pam.d/common-password'

# Account Lockout Configuration
ACCOUNT_LOCKOUT_CONFIG='/etc/pam.d/common-auth'

# SSH Configuration
SSH_CONFIG='/etc/ssh/sshd_config'
SSH_PORT=2222  # Example non-standard SSH port

# File Types to Remove (non-work related media)
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")

# Hacking Tools to Remove
HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack")

# Unnecessary Packages
UNNECESSARY_PACKAGES=("libreoffice*" "thunderbird*" "transmission*" "brasero*" "gnome-games*" "aisleriot*" "gnome-mahjongg*" "gnome-mines*" "gnome-sudoku*" "ftp*" "telnet*" "yelp*" "yelp-xsl*" "samba-common*" "samba-common-bin*" "tcpdump*")

# ------------------------------
# SAFETY NOTE:
# Do NOT remove or disable the CyberPatriot scoring software or CCS Client.
# This script does not specifically target those. If discovered, do not remove them.
# ------------------------------

# ------------------------------
# User Management
# ------------------------------
echo "[*] Managing users..."

# Remove Unauthorized Users (prompt before deletion)
echo "[*] Checking for unauthorized users..."
for user in $(awk -F: '{ print $1 }' /etc/passwd); do
    # Skip system accounts and the nobody user
    USER_ID=$(id -u "$user" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        continue
    fi
    if [ "$USER_ID" -ge 1000 ] && [ "$user" != "nobody" ]; then
        # If user is not in the authorized list, consider removal
        if [[ ! " ${ALL_AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
            echo "[*] Found unauthorized user: $user"
            read -p "Do you want to delete user '$user'? (y/n): " confirm
            if [[ "$confirm" == "y" ]]; then
                userdel -r "$user" &>/dev/null
                if [ $? -eq 0 ]; then
                    echo "[+] User '$user' deleted successfully."
                else
                    echo "[-] Failed to delete user '$user' or user does not exist."
                fi
            else
                echo "[*] Skipping deletion of user '$user'."
            fi
        fi
    fi
done

# ------------------------------
# Administrator Privileges
# ------------------------------
echo "[*] Configuring administrator privileges..."

# Remove unauthorized users from sudo group
echo "[*] Removing unauthorized users from the sudo group..."
for user in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
    if [[ " ${AUTHORIZED_ADMINISTRATORS[@]} " =~ " ${user} " ]]; then
        echo "[+] Retaining sudo privileges for administrator: '$user'"
    else
        if [ -n "$user" ]; then
            echo "[*] Removing '$user' from the sudo group."
            deluser "$user" sudo
            if [ $? -eq 0 ]; then
                echo "[+] User '$user' removed from sudo group successfully."
            else
                echo "[-] Failed to remove '$user' from sudo group."
            fi
        fi
    fi
done

# Add administrators to the sudo group
echo "[*] Adding administrators to the sudo group..."
for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
    if id "$admin" &>/dev/null; then
        usermod -aG sudo "$admin"
        if [ $? -eq 0 ]; then
            echo "[+] User '$admin' added to the sudo group."
        else
            echo "[-] Failed to add user '$admin' to sudo group."
        fi
    else
        echo "[-] Administrator '$admin' does not exist on the system."
    fi
done

# ------------------------------
# Password Policy Enforcement
# ------------------------------
echo "[*] Enforcing password policies..."

# Install libpam-pwquality if not installed
echo "[*] Checking if libpam-pwquality is installed..."
if ! dpkg -l | grep -qw libpam-pwquality; then
    apt update
    apt install -y libpam-pwquality
    if [ $? -eq 0 ]; then
        echo "[+] libpam-pwquality installed successfully."
    else
        echo "[-] Failed to install libpam-pwquality."
        exit 1
    fi
else
    echo "[+] libpam-pwquality is already installed."
fi

echo "[*] Configuring password strength requirements..."
cp "$PASSWORD_STRENGTH" "$PASSWORD_STRENGTH.bak"
sed -i "/pam_unix.so/ s/$/ minlen=$MIN_PASS_LENGTH remember=5/" "$PASSWORD_STRENGTH"
sed -i "/pam_pwquality.so/ s/retry=3/retry=3 minlen=$MIN_PASS_LENGTH difok=3 $PASSWORD_COMPLEXITY/" "$PASSWORD_STRENGTH"

if [ $? -eq 0 ]; then
    echo "[+] Password strength requirements updated."
else
    echo "[-] Failed to update password strength requirements."
fi

# Configure Password Aging in /etc/login.defs
echo "[*] Configuring password aging settings..."
sed -i.bak -E "s/^(PASS_MAX_DAYS\s+)([0-9]+)/\1$PASS_MAX_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_DAYS\s+)([0-9]+)/\1$PASS_MIN_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_WARN_AGE\s+)([0-9]+)/\1$PASS_WARN_AGE/" /etc/login.defs

if [ $? -eq 0 ]; then
    echo "[+] Password aging settings updated."
else
    echo "[-] Failed to update password aging settings."
fi

# ------------------------------
# Account Lockout Configuration
# ------------------------------
echo "[*] Configuring account lockout settings..."
cp "$ACCOUNT_LOCKOUT_CONFIG" "$ACCOUNT_LOCKOUT_CONFIG.bak"
if ! grep -q "pam_tally2.so" "$ACCOUNT_LOCKOUT_CONFIG"; then
    echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> "$ACCOUNT_LOCKOUT_CONFIG"
fi
if [ $? -eq 0 ]; then
    echo "[+] Account lockout settings configured."
else
    echo "[-] Failed to configure account lockout settings."
fi

# ------------------------------
# Firewall Configuration (UFW)
# ------------------------------
echo "[*] Configuring the firewall (UFW)..."

if ! dpkg -l | grep -qw ufw; then
    apt update && apt install -y ufw
    if [ $? -eq 0 ]; then
        echo "[+] UFW installed successfully."
    else
        echo "[-] Failed to install UFW."
        exit 1
    fi
else
    echo "[+] UFW is already installed."
fi

echo "[*] Enabling UFW..."
ufw --force enable
if [ $? -eq 0 ]; then
    echo "[+] UFW enabled successfully."
else
    echo "[-] Failed to enable UFW."
fi

echo "[*] Allowing SSH on port $SSH_PORT..."
ufw allow "$SSH_PORT"/tcp
if [ $? -eq 0 ]; then
    echo "[+] SSH port $SSH_PORT allowed through UFW."
else
    echo "[-] Failed to allow SSH port $SSH_PORT through UFW."
fi

ufw delete allow OpenSSH &>/dev/null
ufw logging on

# ------------------------------
# SSH Configuration
# ------------------------------
echo "[*] Configuring SSH..."
if [ -f "$SSH_CONFIG" ]; then
    cp "$SSH_CONFIG" "$SSH_CONFIG.bak"
    sed -i "s/^#Port .*/Port $SSH_PORT/" "$SSH_CONFIG"
    sed -i "s/^Port 22/Port $SSH_PORT/" "$SSH_CONFIG"
    systemctl restart ssh
    echo "[+] SSH port updated and service restarted."
else
    echo "[-] SSH config file not found at $SSH_CONFIG."
fi

# ------------------------------
# Automatic Updates and Upgrades
# ------------------------------
echo "[*] Setting up automatic system updates..."

if ! dpkg -l | grep -qw unattended-upgrades; then
    apt update && apt install -y unattended-upgrades
    if [ $? -eq 0 ]; then
        echo "[+] unattended-upgrades installed successfully."
    else
        echo "[-] Failed to install unattended-upgrades."
        exit 1
    fi
else
    echo "[+] unattended-upgrades is already installed."
fi

dpkg-reconfigure --priority=low unattended-upgrades

cat <<EOF > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
echo "[+] Daily update checks configured."

apt update && apt upgrade -y
if [ $? -eq 0 ]; then
    echo "[+] Packages upgraded successfully."
else
    echo "[-] Failed to upgrade packages."
fi

cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
echo "[+] Automatic reboots for security updates configured."

# ------------------------------
# Install and Set Google Chrome as Default Browser
# ------------------------------
echo "[*] Ensuring Google Chrome is installed..."

if ! dpkg -l | grep -qw google-chrome-stable; then
    apt update
    # Add Google Chrome repository and install
    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add -
    echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | tee /etc/apt/sources.list.d/google-chrome.list
    apt update && apt install -y google-chrome-stable
    if [ $? -eq 0 ]; then
        echo "[+] Google Chrome installed successfully."
        update-alternatives --set x-www-browser /usr/bin/google-chrome-stable
        echo "[+] Google Chrome set as the default browser."
    else
        echo "[-] Failed to install Google Chrome."
    fi
else
    echo "[+] Google Chrome is already installed."
    update-alternatives --set x-www-browser /usr/bin/google-chrome-stable
    echo "[+] Google Chrome set as the default browser."
fi

# ------------------------------
# Squid Proxy Server Configuration
# ------------------------------
echo "[*] Ensuring Squid proxy server is installed and configured..."

if ! dpkg -l | grep -qw squid; then
    apt update && apt install -y squid
    if [ $? -eq 0 ]; then
        echo "[+] Squid installed successfully."
    else
        echo "[-] Failed to install Squid."
    fi
else
    echo "[+] Squid is already installed."
fi

# Basic hardening of Squid configuration
SQUID_CONF="/etc/squid/squid.conf"
if [ -f "$SQUID_CONF" ]; then
    cp "$SQUID_CONF" "$SQUID_CONF.bak"
    # Example secure configuration adjustments:
    # Restrict access, deny unknown networks, enable basic logging
    sed -i 's/http_access allow localnet/http_access allow localhost/' "$SQUID_CONF"
    sed -i 's/http_access deny all/http_access deny !localhost/' "$SQUID_CONF"
    systemctl restart squid
    if [ $? -eq 0 ]; then
        echo "[+] Squid configuration updated and service restarted."
    else
        echo "[-] Failed to restart Squid after configuration changes."
    fi
else
    echo "[-] Squid configuration file not found."
fi

# ------------------------------
# File Management (Remove Non-Work Related Media)
# ------------------------------
echo "[*] Managing media files..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
    echo "[*] Finding files matching '$pattern'..."
    find /home /root -type f -iname "$pattern" 2>/dev/null | while read -r file; do
        echo "[*] Found file: $file"
        read -p "Do you want to delete '$file'? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then
            rm -f "$file"
            if [ $? -eq 0 ]; then
                echo "[+] File '$file' deleted."
            else
                echo "[-] Failed to delete file '$file'."
            fi
        else
            echo "[*] Skipping deletion of '$file'."
        fi
    done
done

# ------------------------------
# Package Management
# ------------------------------
echo "[*] Removing unnecessary packages..."
for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
    echo "[*] Purging package '$pkg'..."
    apt purge -y "$pkg"
    if [ $? -eq 0 ]; then
        echo "[+] Package '$pkg' removed."
    else
        echo "[-] Failed to remove package '$pkg' or it may not exist."
    fi
done

echo "[*] Checking and removing hacking tools..."
for tool in "${HACKER_TOOLS[@]}"; do
    if dpkg -l | grep -qw "$tool"; then
        echo "[*] Removing $tool..."
        apt remove --purge -y "$tool"
        if [ $? -eq 0 ]; then
            echo "[+] $tool removed."
        else
            echo "[-] Failed to remove $tool."
        fi
    else
        echo "[+] $tool not installed."
    fi
done

apt autoremove -y
if [ $? -eq 0 ]; then
    echo "[+] Residual dependencies cleaned."
else
    echo "[-] Failed to clean up residual dependencies."
fi

# ------------------------------
# Service Configuration
# ------------------------------
echo "[*] Configuring services..."

# Disable avahi-daemon if present
if systemctl list-unit-files | grep -qw avahi-daemon.service; then
    if systemctl is-enabled --quiet avahi-daemon; then
        systemctl disable --now avahi-daemon
        if [ $? -eq 0 ]; then
            echo "[+] avahi-daemon disabled."
        else
            echo "[-] Failed to disable avahi-daemon."
        fi
    else
        echo "[+] avahi-daemon already disabled."
    fi
else
    echo "[+] avahi-daemon not installed."
fi

# Disable Apache2 if present
if systemctl list-unit-files | grep -qw apache2.service; then
    if systemctl is-enabled --quiet apache2; then
        systemctl disable --now apache2
        if [ $? -eq 0 ]; then
            echo "[+] Apache2 disabled."
        else
            echo "[-] Failed to disable Apache2."
        fi
    else
        echo "[+] Apache2 already disabled."
    fi
fi

# Disable Nginx if present
if systemctl list-unit-files | grep -qw nginx.service; then
    if systemctl is-enabled --quiet nginx; then
        systemctl disable --now nginx
        if [ $? -eq 0 ]; then
            echo "[+] Nginx disabled."
        else
            echo "[-] Failed to disable Nginx."
        fi
    else
        echo "[+] Nginx already disabled."
    fi
fi

# DO NOT disable or remove the CyberPatriot scoring software or CCS client if present
# (No code here specifically targeting CCS Client or scoring software)

# ------------------------------
# Final Steps
# ------------------------------
echo "[+] Security Hardening and User Management Completed Successfully on Ubuntu 22.04."
exit 0
