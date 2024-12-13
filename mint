#!/bin/bash

# ==================================================
# Comprehensive Security Hardening and User Management Script for Linux Mint
# Combined Script: User and Password Policy + Missing Security Hardening Steps
# ==================================================
# This script performs the following tasks:
# - Removes unauthorized users.
# - Assigns administrators to the sudo group.
# - Removes unauthorized users from the sudo group.
# - Enforces password policies and password aging.
# - Configures a firewall (UFW) and custom SSH port.
# - Sets up automatic updates and unattended upgrades.
# - Enables account lockout after multiple failed login attempts.
# - Removes unnecessary packages and hacking tools.
# - Disables unnecessary services.
# - Optionally removes certain media files.
# ==================================================

# ------------------------------
# Ensure the script is run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Use sudo."
   exit 1
fi

echo "[+] Starting Comprehensive Security Hardening and User Management Script..."

# ------------------------------
# Logging Configuration
# ------------------------------
LOGFILE="/var/log/security_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------
# Configuration Variables
# ------------------------------

# Define authorized users (retain these users on the system)
AUTHORIZED_USERS=(
    "twellick"
    "jplofe"
    "pmccleery"
    "wbraddock"
    "ealderson"
    "lchong"
    "sswailem"
    "pprice"
    "sknowles"
    "tcolby"
    "jchutney"
    "sweinsberg"
    "sjacobs"
    "lspencer"
    "mralbern"
    "jrobinson"
    "gsheldern"
    "coshearn"
    "jlaslen"
    "kshelvern"
    "jtholdon"
    "belkarn"
    "bharper"
)

# Define administrators (users with sudo privileges)
ADMINISTRATORS=(
    "twellick"
    "jplofe"
    "pmccleery"
    "wbraddock"
    "ealderson"
    "lchong"
    "sswailem"
)

# Password Policy Configuration
MIN_PASS_LENGTH=12
MAX_PASS_LENGTH=24
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
SSH_PORT=2222  # Customize as desired

# File Types to Remove (optional)
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")

# Hacking Tools to Remove
HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack")

# Unnecessary Packages
UNNECESSARY_PACKAGES=("libreoffice*" "thunderbird*" "transmission*" "brasero*" "gnome-games*" "aisleriot*" "gnome-mahjongg*" "gnome-mines*" "gnome-sudoku*" "ftp*" "telnet*" "yelp*" "yelp-xsl*" "samba-common*" "samba-common-bin*" "tcpdump*")

# ------------------------------
# User Management
# ------------------------------
echo "[*] Managing users..."

# Remove Unauthorized Users
echo "[*] Removing unauthorized users..."
for user in $(awk -F: '{ print $1 }' /etc/passwd); do
    if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
        USER_ID=$(id -u "$user" 2>/dev/null)
        if [[ $? -ne 0 ]]; then
            echo "[-] Failed to get UID for user '$user'. Skipping."
            continue
        fi
        if [ "$USER_ID" -ge 1000 ] && [ "$user" != "nobody" ]; then
            echo "[*] Considering deletion of user: $user"
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

# Remove unauthorized users from the sudo group
echo "[*] Removing unauthorized users from the sudo group..."
for user in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
    if [[ " ${ADMINISTRATORS[@]} " =~ " ${user} " ]]; then
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
for admin in "${ADMINISTRATORS[@]}"; do
    if id "$admin" &>/dev/null; then
        usermod -aG sudo "$admin"
        if [ $? -eq 0 ]; then
            echo "[+] User '$admin' added to the sudo group."
        else
            echo "[-] Failed to add user '$admin' to sudo group."
        fi
    else
        echo "[-] Administrator '$admin' does not exist."
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
    echo "[+] Password strength requirements updated successfully."
else
    echo "[-] Failed to update password strength requirements."
fi

# Configure Password Aging in /etc/login.defs
echo "[*] Configuring password aging settings in /etc/login.defs..."
sed -i.bak -E "s/^(PASS_MAX_DAYS\s+)([0-9]+)/\1$PASS_MAX_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_DAYS\s+)([0-9]+)/\1$PASS_MIN_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_WARN_AGE\s+)([0-9]+)/\1$PASS_WARN_AGE/" /etc/login.defs

if [ $? -eq 0 ]; then
    echo "[+] Password aging settings updated successfully."
else
    echo "[-] Failed to update password aging settings."
fi

# ------------------------------
# Account Lockout Configuration
# ------------------------------
echo "[*] Configuring account lockout settings..."
cp "$ACCOUNT_LOCKOUT_CONFIG" "$ACCOUNT_LOCKOUT_CONFIG.bak"
grep -q "pam_tally2.so" "$ACCOUNT_LOCKOUT_CONFIG" || echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> "$ACCOUNT_LOCKOUT_CONFIG"
if [ $? -eq 0 ]; then
    echo "[+] Account lockout settings configured successfully."
else
    echo "[-] Failed to configure account lockout settings."
fi

# ------------------------------
# Firewall Configuration (UFW)
# ------------------------------
echo "[*] Configuring the firewall..."

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

echo "[*] Configuring UFW to allow SSH on port $SSH_PORT..."
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
    echo "[+] SSH port updated to $SSH_PORT and service restarted."
else
    echo "[-] SSH config file not found at $SSH_CONFIG."
fi

# ------------------------------
# Automatic Updates and Upgrades
# ------------------------------
echo "[*] Setting up automatic system updates..."

if ! dpkg -l | grep -qw unattended-upgrades; then
    apt install -y unattended-upgrades
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
# File Management (Optional)
# ------------------------------
echo "[*] Managing files..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
    echo "[*] Finding files matching '$pattern'..."
    find /home /root -type f -iname "$pattern" 2>/dev/null | while read -r file; do
        echo "[*] Found file: $file"
        read -p "Do you want to delete '$file'? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then
            rm -f "$file"
            if [ $? -eq 0 ]; then
                echo "[+] File '$file' deleted successfully."
            else
                echo "[-] Failed to delete file '$file'."
            fi
        else
            echo "[*] Skipping deletion of file '$file'."
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
        echo "[+] Package '$pkg' removed successfully."
    else
        echo "[-] Failed to remove package '$pkg' or it does not exist."
    fi
done

echo "[*] Checking and removing hacking tools..."
for tool in "${HACKER_TOOLS[@]}"; do
    if dpkg -l | grep -qw "$tool"; then
        echo "[*] Removing $tool..."
        apt remove --purge -y "$tool"
        if [ $? -eq 0 ]; then
            echo "[+] $tool removed successfully."
        else
            echo "[-] Failed to remove $tool."
        fi
    else
        echo "[+] $tool is not installed."
    fi
done

apt autoremove -y
if [ $? -eq 0 ]; then
    echo "[+] Residual dependencies cleaned up successfully."
else
    echo "[-] Failed to clean up residual dependencies."
fi

# ------------------------------
# Service Configuration
# ------------------------------
echo "[*] Configuring services..."

# Disable avahi-daemon
if systemctl list-unit-files | grep -qw avahi-daemon.service; then
    if systemctl is-enabled --quiet avahi-daemon; then
        systemctl disable --now avahi-daemon
        if [ $? -eq 0 ]; then
            echo "[+] avahi-daemon disabled successfully."
        else
            echo "[-] Failed to disable avahi-daemon."
        fi
    else
        echo "[+] avahi-daemon is already disabled."
    fi
else
    echo "[+] avahi-daemon is not installed."
fi

# Disable Apache2
if systemctl list-unit-files | grep -qw apache2.service; then
    if systemctl is-enabled --quiet apache2; then
        systemctl disable --now apache2
        if [ $? -eq 0 ]; then
            echo "[+] Apache2 service disabled successfully."
        else
            echo "[-] Failed to disable Apache2 service."
        fi
    else
        echo "[+] Apache2 service is already disabled."
    fi
else
    echo "[+] Apache2 is not installed."
fi

# Disable Nginx
if systemctl list-unit-files | grep -qw nginx.service; then
    if systemctl is-enabled --quiet nginx; then
        systemctl disable --now nginx
        if [ $? -eq 0 ]; then
            echo "[+] Nginx service disabled successfully."
        else
            echo "[-] Failed to disable Nginx service."
        fi
    else
        echo "[+] Nginx service is already disabled."
    fi
else
    echo "[+] Nginx is not installed."
fi

# ------------------------------
# Final Steps
# ------------------------------
echo "[+] Comprehensive Security Hardening and User Management Completed Successfully."

exit 0
