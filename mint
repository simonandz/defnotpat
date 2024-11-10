#!/bin/bash

# ==================================================
# CyberPatriots Security Hardening Script for Ubuntu 22.04
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
AUTHORIZED_USERS=(
    "jaimie" "adalbern" "amayas" "fabienne" "mariya" "cornelius" "harold"
    "taran" "felix" "angela" "rais" "miriam" "aldo" "timothy" "leilani"
    "viktor" "linda" "jeanne" "martin" "josef" "roger" "stacy" "suzy" "liz"
)

# Define administrators (users with sudo privileges)
ADMINISTRATORS=("perry" "carlos" "kan" "alice" "josefina")

# Define group authorizations (group: authorized members)
declare -A GROUPS_AUTHORIZED=(
    ["adm"]="syslog"
    ["sudo"]="perry,carlos,kan,alice,josefina"
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
SSH_PORT=22  # Keep the default SSH port

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
    if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]] && [[ ! " ${ADMINISTRATORS[@]} " =~ " ${user} " ]]; then
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

# 5. Add 'mariya' to the 'pioneers' group
echo "[*] Adding 'mariya' to the 'pioneers' group..."
if id "mariya" &>/dev/null; then
    groupadd -f pioneers
    usermod -aG pioneers mariya
    if [ $? -eq 0 ]; then
        echo "[+] 'mariya' added to the 'pioneers' group."
    else
        echo "[-] Failed to add 'mariya' to the 'pioneers' group."
    fi
else
    echo "[-] User 'mariya' does not exist."
fi

# ------------------------------
# Firewall Configuration
# ------------------------------
echo "[*] Configuring the firewall..."

# 6. Enable and Update Firewall (UFW)
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

# 7. Allow SSH through the Firewall
echo "[*] Configuring UFW to allow SSH on port $SSH_PORT..."
ufw allow "$SSH_PORT"/tcp
if [ $? -eq 0 ]; then
    echo "[+] SSH port $SSH_PORT allowed through UFW."
else
    echo "[-] Failed to allow SSH port $SSH_PORT through UFW."
fi

# Remove default SSH rule if exists
ufw delete allow OpenSSH &>/dev/null

# 8. Enable UFW Logging
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

# 9. Enable Automatic Updates and Check for Updates Daily
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

# 10. Upgrade All Packages
echo "[*] Upgrading all packages to the latest versions..."
apt update && apt upgrade -y
if [ $? -eq 0 ]; then
    echo "[+] Packages upgraded successfully."
else
    echo "[-] Failed to upgrade packages."
fi

# 11. Enable Automatic Reboots for Security Updates
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

# 12. Remove Specified Media Files
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

# 13. Update Password Requirements
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

# 14. Configure Account Lockout
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

# 15. Configure Password Aging in /etc/login.defs
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
# SSH Configuration
# ------------------------------
echo "[*] Configuring SSH..."

# 16. Apply SSH Configuration
echo "[*] Backing up SSH configuration..."
cp "$SSH_CONFIG" "$SSH_CONFIG.bak"

echo "[*] Modifying SSH configuration..."

# Use sed to modify specific settings
sed -i "s/^#Port 22/Port $SSH_PORT/" "$SSH_CONFIG"
sed -i "s/^Port [0-9]*/Port $SSH_PORT/" "$SSH_CONFIG"
sed -i "s/^#PermitRootLogin prohibit-password/PermitRootLogin no/" "$SSH_CONFIG"
sed -i "s/^PermitRootLogin yes/PermitRootLogin no/" "$SSH_CONFIG"
sed -i "s/^#UsePAM yes/UsePAM yes/" "$SSH_CONFIG"
sed -i "s/^#X11Forwarding yes/X11Forwarding yes/" "$SSH_CONFIG"
sed -i "s/^#PrintMotd no/PrintMotd no/" "$SSH_CONFIG"
sed -i "s/^#AcceptEnv LANG LC_\*/AcceptEnv LANG LC_\*/" "$SSH_CONFIG"
sed -i "s/^#Subsystem sftp/Subsystem sftp/" "$SSH_CONFIG"
sed -i "s/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/" "$SSH_CONFIG"
sed -i "s/^ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/" "$SSH_CONFIG"

if [ $? -eq 0 ]; then
    echo "[+] SSH configuration updated successfully."
else
    echo "[-] Failed to update SSH configuration."
fi

# 17. Restart SSH Service to Apply Changes
echo "[*] Restarting SSH service..."
if systemctl is-active --quiet ssh; then
    systemctl restart ssh
    if [ $? -eq 0 ]; then
        echo "[+] SSH service restarted successfully."
    else
        echo "[-] Failed to restart SSH service."
    fi
else
    echo "[-] SSH service is not active. Starting SSH service..."
    systemctl start ssh
    if [ $? -eq 0 ]; then
        echo "[+] SSH service started successfully."
    else
        echo "[-] Failed to start SSH service."
    fi
fi

# ------------------------------
# Package Management
# ------------------------------
echo "[*] Managing packages..."

# 18. Ensure Firefox is installed from the official Mozilla PPA
echo "[*] Configuring Firefox installation..."
snap remove firefox &>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] Removed Firefox SNAP package."
fi

add-apt-repository -y ppa:mozillateam/ppa
echo 'Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001' | tee /etc/apt/preferences.d/mozilla-firefox
apt update
apt install -y firefox
if [ $? -eq 0 ]; then
    echo "[+] Firefox installed from Mozilla PPA."
else
    echo "[-] Failed to install Firefox from Mozilla PPA."
fi

# 19. Ensure Thunderbird is installed
echo "[*] Ensuring Thunderbird is installed..."
apt install -y thunderbird
if [ $? -eq 0 ]; then
    echo "[+] Thunderbird is installed and up to date."
else
    echo "[-] Failed to install Thunderbird."
fi

# 20. Ensure Perl is installed
echo "[*] Ensuring Perl is installed..."
apt install -y perl
if [ $? -eq 0 ]; then
    echo "[+] Perl is installed."
else
    echo "[-] Failed to install Perl."
fi

# 21. Remove Unnecessary Packages
echo "[*] Removing unnecessary packages..."
UNNECESSARY_PACKAGES=("libreoffice*" "transmission*" "brasero*" "gnome-games*" "aisleriot*" "gnome-mahjongg*" "gnome-mines*" "gnome-sudoku*" "ftp*" "telnet*" "yelp*" "yelp-xsl*" "samba-common*" "samba-common-bin*" "tcpdump*")
for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
    echo "[*] Purging package '$pkg'..."
    apt purge -y "$pkg"
    if [ $? -eq 0 ]; then
        echo "[+] Package '$pkg' removed successfully."
    else
        echo "[-] Failed to remove package '$pkg' or it does not exist."
    fi
done

# 22. Remove Hacking Tools
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

# 23. Disable avahi-daemon
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

# 24. Disable Apache2 Service
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

# 25. Disable Nginx Service
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

# 26. Disable FTP Services if Installed
echo "[*] Disabling FTP services if installed..."
FTP_SERVICES=("vsftpd" "proftpd" "pure-ftpd")
for ftp_service in "${FTP_SERVICES[@]}"; do
    if systemctl list-unit-files | grep -qw "$ftp_service.service"; then
        if systemctl is-active --quiet "$ftp_service"; then
            systemctl disable --now "$ftp_service"
            if [ $? -eq 0 ]; then
                echo "[+] '$ftp_service' service disabled."
            else
                echo "[-] Failed to disable '$ftp_service' service."
            fi
        else
            echo "[+] '$ftp_service' service is not active."
        fi
    else
        echo "[+] '$ftp_service' service is not installed."
    fi
done

# 27. Install and Configure Fail2Ban
echo "[*] Installing and configuring Fail2Ban..."
if ! dpkg -l | grep -qw fail2ban; then
    apt install -y fail2ban
    if [ $? -eq 0 ]; then
        echo "[+] Fail2Ban installed successfully."
    else
        echo "[-] Failed to install Fail2Ban."
        exit 1
    fi
else
    echo "[+] Fail2Ban is already installed."
fi

# Configure Fail2Ban for SSH
echo "[*] Configuring Fail2Ban for SSH..."
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 600
findtime  = 600
maxretry = 5

[sshd]
enabled = true
port    = $SSH_PORT
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
if [ $? -eq 0 ]; then
    echo "[+] Fail2Ban configuration updated successfully."
    systemctl restart fail2ban
    systemctl enable fail2ban
    if [ $? -eq 0 ]; then
        echo "[+] Fail2Ban restarted and enabled successfully."
    else
        echo "[-] Failed to restart or enable Fail2Ban."
    fi
else
    echo "[-] Failed to configure Fail2Ban."
fi

# 28. Install X2GO Server
echo "[*] Installing X2GO server..."
add-apt-repository -y ppa:x2go/stable
apt update
apt install -y x2goserver x2goserver-xsession
if [ $? -eq 0 ]; then
    echo "[+] X2GO server installed successfully."
else
    echo "[-] Failed to install X2GO server."
fi

# ------------------------------
# Audit and Monitoring
# ------------------------------
echo "[*] Setting up audit and monitoring tools..."

# 29. Install and Configure Auditd
echo "[*] Installing auditd..."
if ! dpkg -l | grep -qw auditd; then
    apt install -y auditd audispd-plugins
    if [ $? -eq 0 ]; then
        echo "[+] auditd installed successfully."
    else
        echo "[-] Failed to install auditd."
        exit 1
    fi
else
    echo "[+] auditd is already installed."
fi

# Start and enable auditd
echo "[*] Starting and enabling auditd service..."
systemctl start auditd
if [ $? -eq 0 ]; then
        echo "[+] auditd service started successfully."
else
    echo "[-] Failed to start auditd service."
fi

systemctl enable auditd
if [ $? -eq 0 ]; then
    echo "[+] auditd service enabled to start on boot."
else
    echo "[-] Failed to enable auditd service."
fi

# 30. Configure Audit Rules
echo "[*] Configuring audit rules..."
cat <<EOF > /etc/audit/rules.d/audit.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes
-w /var/log/auth.log -p wa -k auth_log_changes
EOF
if [ $? -eq 0 ]; then
    echo "[+] Audit rules configured successfully."
    systemctl restart auditd
    if [ $? -eq 0 ]; then
        echo "[+] auditd service restarted to apply new rules."
    else
        echo "[-] Failed to restart auditd service."
    fi
else
    echo "[-] Failed to configure audit rules."
fi

# 31. Install and Configure Logwatch
echo "[*] Installing Logwatch for log monitoring..."
if ! dpkg -l | grep -qw logwatch; then
    apt install -y logwatch
    if [ $? -eq 0 ]; then
        echo "[+] Logwatch installed successfully."
    else
        echo "[-] Failed to install Logwatch."
        exit 1
    fi
else
    echo "[+] Logwatch is already installed."
fi

# Configure Logwatch to send reports daily
echo "[*] Configuring Logwatch..."
LOGWATCH_CONF="/usr/share/logwatch/default.conf/logwatch.conf"
cp "$LOGWATCH_CONF" "$LOGWATCH_CONF.bak"
sed -i 's/^Output = stdout/Output = mail/' "$LOGWATCH_CONF"
sed -i 's/^MailTo = root/MailTo = root/' "$LOGWATCH_CONF"  # Assuming root mail is monitored
sed -i 's/^Detail = Low/Detail = High/' "$LOGWATCH_CONF"
if [ $? -eq 0 ]; then
    echo "[+] Logwatch configured successfully."
else
    echo "[-] Failed to configure Logwatch."
fi

# ------------------------------
# Final Steps
# ------------------------------
echo "[+] CyberPatriots Security Hardening Completed Successfully."

exit 0
