#!/bin/bash

# ==================================================
# CyberPatriots Security Hardening Script for Linux Mint
# Enhanced Version with Improved Security Measures
# ==================================================
# This script performs essential security hardening steps
# required for the CyberPatriots competition.
# ==================================================

# ------------------------------
# Ensure the script is run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Use sudo." 
   exit 1
fi

echo "[+] Starting CyberPatriots Security Hardening Script..."

# ------------------------------
# Configuration Variables
# ------------------------------

# Logging Configuration
LOGFILE="/var/log/cyberpatriots_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Define authorized users (retain these users on the system)
AUTHORIZED_USERS=("your_username")  # Replace 'your_username' with actual usernames

# Define administrators (users with sudo privileges)
ADMINISTRATORS=("admin_username")  # Replace 'admin_username' with actual admin usernames

# Define group authorizations (group: authorized members)
declare -A GROUPS_AUTHORIZED=(
    ["adm"]="syslog"
    ["sudo"]="admin_username"  # Replace 'admin_username' with actual admin usernames
    # Add other groups as needed
)

# Define users with specific shells (restrict login capabilities)
declare -A USERS_AUTHORIZED=(
    ["daemon"]="/usr/sbin/nologin"
    ["bin"]="/usr/sbin/nologin"
    ["sys"]="/usr/sbin/nologin"
    # Do not change root's shell
    # Add other system users as needed
)

# Password Policy Configuration
MIN_PASS_LENGTH=12        # Set minimum password length
MAX_PASS_LENGTH=24        # Set maximum password length
PASSWORD_COMPLEXITY="ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"  # Define password complexity

# Password Expiration Settings
PASS_MAX_DAYS=90           # Maximum number of days a password can be used
PASS_MIN_DAYS=10           # Minimum number of days between password changes
PASS_WARN_AGE=7            # Days before password expiration to warn the user

# Account Lockout Configuration
ACCOUNT_LOCKOUT_CONFIG='/etc/pam.d/common-auth'
ACCOUNT_LOCKOUT_CONTENT=(
    "# Authentication settings common to all services"
    "auth    required    pam_tally2.so deny=5 onerr=fail unlock_time=1800"
)

# Password Strength Configuration
PASSWORD_STRENGTH='/etc/pam.d/common-password'

# SSH Configuration
SSH_CONFIG='/etc/ssh/sshd_config'
SSH_PORT=2222  # Set your desired SSH port (e.g., 2222)

# File Types to Remove
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")

# Hacking Tools to Remove
HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack")

# ------------------------------
# User and Permissions Management
# ------------------------------
echo "[*] Managing users and permissions..."

# 1. Delete Unauthorized Users
echo "[*] Deleting unauthorized users..."
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

# 2. Configure Administrator Privileges
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

# 3. Set User Shells as per USERS_AUTHORIZED
echo "[*] Setting user shells as per authorized configurations..."
for user in "${!USERS_AUTHORIZED[@]}"; do
    if id "$user" &>/dev/null; then
        current_shell=$(getent passwd "$user" | cut -d: -f7)
        desired_shell=${USERS_AUTHORIZED[$user]}
        if [[ "$current_shell" != "$desired_shell" ]]; then
            echo "[*] Changing shell for user '$user' to '$desired_shell'"
            usermod -s "$desired_shell" "$user"
            if [ $? -eq 0 ]; then
                echo "[+] Shell for user '$user' changed successfully."
            else
                echo "[-] Failed to change shell for user '$user'."
            fi
        else
            echo "[+] User '$user' already has the desired shell."
        fi
        # Secure the home directory
        user_home=$(getent passwd "$user" | cut -d: -f6)
        chmod 700 "$user_home"
        if [ $? -eq 0 ]; then
            echo "[+] Permissions for home directory of '$user' set to 700."
        else
            echo "[-] Failed to set permissions for home directory of '$user'."
        fi
    else
        echo "[-] User '$user' does not exist."
    fi
done

# 4. Manage Group Memberships as per GROUPS_AUTHORIZED
echo "[*] Managing group memberships as per authorized configurations..."
for group in "${!GROUPS_AUTHORIZED[@]}"; do
    authorized_members=${GROUPS_AUTHORIZED[$group]}
    IFS=',' read -ra AUTH_MEMBERS <<< "$authorized_members"

    # Get current members
    current_members=$(getent group "$group" | awk -F: '{print $4}')
    IFS=',' read -ra CURRENT_MEMBERS_ARRAY <<< "$current_members"

    # Remove unauthorized members
    for member in "${CURRENT_MEMBERS_ARRAY[@]}"; do
        if [[ -n "$member" && ! " ${AUTH_MEMBERS[@]} " =~ " ${member} " ]]; then
            echo "[*] Removing user '$member' from group '$group'"
            deluser "$member" "$group"
            if [ $? -eq 0 ]; then
                echo "[+] User '$member' removed from group '$group' successfully."
            else
                echo "[-] Failed to remove user '$member' from group '$group'."
            fi
        fi
    done

    # Add authorized members
    for authorized_member in "${AUTH_MEMBERS[@]}"; do
        if [[ -n "$authorized_member" ]]; then
            if id "$authorized_member" &>/dev/null; then
                echo "[*] Adding user '$authorized_member' to group '$group'"
                usermod -aG "$group" "$authorized_member"
                if [ $? -eq 0 ]; then
                    echo "[+] User '$authorized_member' added to group '$group' successfully."
                else
                    echo "[-] Failed to add user '$authorized_member' to group '$group'."
                fi
            else
                echo "[-] Authorized user '$authorized_member' does not exist."
            fi
        fi
    done
done

# ------------------------------
# Firewall Configuration
# ------------------------------
echo "[*] Configuring the firewall..."

# 5. Enable and Update Firewall (UFW)
echo "[*] Installing and enabling UFW (Uncomplicated Firewall)..."
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

# 6. Allow SSH through the Firewall
echo "[*] Configuring UFW to allow SSH on port $SSH_PORT..."
ufw allow "$SSH_PORT"/tcp
if [ $? -eq 0 ]; then
    echo "[+] SSH port $SSH_PORT allowed through UFW."
else
    echo "[-] Failed to allow SSH port $SSH_PORT through UFW."
fi

# Remove default SSH rule if exists
ufw delete allow OpenSSH &>/dev/null

# 7. Enable UFW Logging
echo "[*] Enabling UFW logging..."
ufw logging on
if [ $? -eq 0 ]; then
    echo "[+] UFW logging enabled."
else
    echo "[-] Failed to enable UFW logging."
fi

# ------------------------------
# System Updates and Upgrades
# ------------------------------
echo "[*] Setting up automatic system updates..."

# 8. Enable Automatic Updates and Check for Updates Daily
echo "[*] Installing unattended-upgrades..."
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

echo "[*] Configuring unattended-upgrades..."
dpkg-reconfigure --priority=low unattended-upgrades
if [ $? -eq 0 ]; then
    echo "[+] unattended-upgrades configured successfully."
else
    echo "[-] Failed to configure unattended-upgrades."
fi

# Configure daily update checks
echo "[*] Configuring daily update checks..."
cat <<EOF > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
if [ $? -eq 0 ]; then
    echo "[+] Daily update checks configured."
else
    echo "[-] Failed to configure daily update checks."
fi

# 9. Upgrade All Packages
echo "[*] Upgrading all packages to the latest versions..."
apt update && apt upgrade -y
if [ $? -eq 0 ]; then
    echo "[+] Packages upgraded successfully."
else
    echo "[-] Failed to upgrade packages."
fi

# 10. Enable Automatic Reboots for Security Updates
echo "[*] Configuring automatic reboots for security updates..."
cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
if [ $? -eq 0 ]; then
    echo "[+] Automatic reboots for security updates configured."
else
    echo "[-] Failed to configure automatic reboots."
fi

# ------------------------------
# File Management
# ------------------------------
echo "[*] Managing files..."

# 11. Remove Specified Media Files
echo "[*] Deleting specified media files..."
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
# Password Policy Enforcement
# ------------------------------
echo "[*] Enforcing strong password policies..."

# 12. Update Password Requirements
echo "[*] Installing libpam-pwquality..."
if ! dpkg -l | grep -qw libpam-pwquality; then
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

# Backup the original file
cp "$PASSWORD_STRENGTH" "$PASSWORD_STRENGTH.bak"

# Modify specific settings using sed
sed -i "/pam_unix.so/ s/$/ minlen=$MIN_PASS_LENGTH remember=5/" "$PASSWORD_STRENGTH"
sed -i "/pam_pwquality.so/ s/retry=3/retry=3 minlen=$MIN_PASS_LENGTH difok=3 $PASSWORD_COMPLEXITY/" "$PASSWORD_STRENGTH"

if [ $? -eq 0 ]; then
    echo "[+] Password strength requirements updated successfully."
else
    echo "[-] Failed to update password strength requirements."
fi

# 13. Configure Account Lockout
echo "[*] Configuring account lockout settings..."
# Backup the original file
cp "$ACCOUNT_LOCKOUT_CONFIG" "$ACCOUNT_LOCKOUT_CONFIG.bak"

# Add the account lockout line if not already present
grep -q "pam_tally2.so" "$ACCOUNT_LOCKOUT_CONFIG" || echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> "$ACCOUNT_LOCKOUT_CONFIG"

if [ $? -eq 0 ]; then
    echo "[+] Account lockout settings configured successfully."
else
    echo "[-] Failed to configure account lockout settings."
fi

# 14. Configure Password Aging in /etc/login.defs
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
# Package Management
# ------------------------------
echo "[*] Managing packages..."

# 15. Remove Unnecessary Packages
echo "[*] Removing unnecessary packages..."
UNNECESSARY_PACKAGES=("libreoffice*" "thunderbird*" "transmission*" "brasero*" "gnome-games*" "aisleriot*" "gnome-mahjongg*" "gnome-mines*" "gnome-sudoku*" "ftp*" "telnet*" "yelp*" "yelp-xsl*" "samba-common*" "samba-common-bin*" "tcpdump*")
for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
    echo "[*] Purging package '$pkg'..."
    apt purge -y "$pkg"
    if [ $? -eq 0 ]; then
        echo "[+] Package '$pkg' removed successfully."
    else
        echo "[-] Failed to remove package '$pkg' or it does not exist."
    fi
done

# 16. Remove Hacking Tools
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

# Clean up residual dependencies
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

# 17. Disable avahi-daemon
echo "[*] Disabling avahi-daemon if installed..."
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

# 18. Disable Apache2 Service
echo "[*] Disabling Apache2 service if installed..."
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

# 19. Disable Nginx Service
echo "[*] Disabling Nginx service if installed..."
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
echo "[+] CyberPatriots Security Hardening Completed Successfully."

exit 0
