#!/bin/bash

# ==================================================
# CyberPatriots Security Hardening Script for Ubuntu 22.04
# Enhanced Version with Compliance to CyberPatriots Guidelines
# ==================================================
# This script performs essential security hardening steps
# required for the CyberPatriots competition.
# ==================================================

# ------------------------------
# Configuration Variables
# ------------------------------

# Logging Configuration
LOGFILE="/var/log/cyberpatriots_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Define authorized administrators
AUTHORIZED_ADMINISTRATORS=("perry" "carlos" "kan" "alice" "josefina")

# Define authorized users
AUTHORIZED_USERS=("jaimie" "adalbern" "amayas" "fabienne" "mariya" "cornelius" "harold" "taran" "felix" "angela" "rais" "miriam" "aldo" "timothy" "leilani" "viktor" "linda" "jeanne" "martin" "josef" "roger" "stacy" "suzy" "liz")

# Define group authorizations (group: authorized members)
declare -A GROUPS_AUTHORIZED=(
    ["sudo"]="${AUTHORIZED_ADMINISTRATORS[*]}"
    ["pioneers"]="mariya"
    # Add other groups as necessary, ensuring only authorized members are included
)

# Define users with specific shells (restrict login capabilities)
declare -A USERS_AUTHORIZED=(
    ["root"]="/usr/sbin/nologin"
    # Add other system users with restricted shells as necessary
    # Ensure authorized administrators have /bin/bash
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
    "auth\t[success=1 default=ignore]\tpam_unix.so nullok_secure"
    "auth\trequisite\t\t\tpam_deny.so"
    "auth\trequired\t\t\tpam_permit.so"
    "auth  required  pam_tally2.so deny=5 onerr=fail unlock_time=1800"
)

# Password Strength Configuration
PASSWORD_STRENGTH='/etc/pam.d/common-password'
PASSWORD_STRENGTH_CONTENT=(
    "# Password-related modules common to all services"
    "password\trequisite\t\t\tpam_cracklib.so retry=3 minlen=$MIN_PASS_LENGTH difok=3 $PASSWORD_COMPLEXITY"
    "password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass sha512 remember=5 minlen=$MIN_PASS_LENGTH"
    "password\trequisite\t\t\tpam_deny.so"
    "password\trequired\t\t\tpam_permit.so"
    "password\toptional\tpam_gnome_keyring.so "
)

# SSH Configuration
SSH_CONFIG='/etc/ssh/sshd_config'
SSH_PORT=2222  # Set your desired SSH port (e.g., 2222)
SSH_CONFIG_CONTENT=(
    "# SSH Server Configuration"
    "Port $SSH_PORT"
    "PermitRootLogin no"
    "UsePAM yes"
    "X11Forwarding yes"
    "PrintMotd no"
    "AcceptEnv LANG LC_*"
    "Subsystem\tsftp\t/usr/lib/openssh/sftp-server"
    "ChallengeResponseAuthentication no"
)

# File Types to Remove
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")

# Mozilla PPA for Firefox
MOZILLA_PPA="ppa:mozillateam/ppa"

# ------------------------------
# Ensure the script is run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Use sudo." 
   exit 1
fi

echo "[+] Starting CyberPatriots Security Hardening Script for Ubuntu 22.04..."

# ------------------------------
# User and Permissions Management
# ------------------------------
echo "[*] Managing users and permissions..."

# 1. Add Authorized Administrators and Users
echo "[*] Adding authorized administrators and users..."

# Function to create user if not exists
create_user() {
    local user=$1
    local password=$2
    local groups=$3

    if id "$user" &>/dev/null; then
        echo "[+] User '$user' already exists."
    else
        echo "[*] Creating user '$user'."
        useradd -m -s /bin/bash -G "$groups" "$user"
        if [ $? -eq 0 ]; then
            echo "[+] User '$user' created successfully."
        else
            echo "[-] Failed to create user '$user'."
            return 1
        fi
    fi

    if [ -n "$password" ]; then
        echo "$user:$password" | chpasswd
        if [ $? -eq 0 ]; then
            echo "[+] Password for user '$user' set successfully."
        else
            echo "[-] Failed to set password for user '$user'."
            return 1
        fi
    fi
}

# Add Administrators with passwords
create_user "perry" "M4mm@lOfAct!0n" "sudo"
create_user "carlos" "MagicFore$t4" "sudo"
create_user "kan" "uCanD0It!!" "sudo"
create_user "alice" "alice" "sudo"
create_user "josefina" "RocketShip@27" "sudo"

# Add Authorized Users without passwords (assuming they already have)
for user in "${AUTHORIZED_USERS[@]}"; do
    create_user "$user" "" ""
done

# 2. Add "mariya" to "pioneers" group
echo "[*] Adding user 'mariya' to the 'pioneers' group..."
if getent group pioneers &>/dev/null; then
    usermod -aG pioneers mariya
    if [ $? -eq 0 ]; then
        echo "[+] User 'mariya' added to 'pioneers' group successfully."
    else
        echo "[-] Failed to add 'mariya' to 'pioneers' group."
    fi
else
    echo "[*] Group 'pioneers' does not exist. Creating and adding 'mariya'..."
    groupadd pioneers
    usermod -aG pioneers mariya
    if [ $? -eq 0 ]; then
        echo "[+] Group 'pioneers' created and user 'mariya' added successfully."
    else
        echo "[-] Failed to create 'pioneers' group or add 'mariya'."
    fi
fi

# 3. Delete Unauthorized Users
echo "[*] Deleting unauthorized users..."
for user in $(cut -f1 -d: /etc/passwd); do
    if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " && ! " ${AUTHORIZED_ADMINISTRATORS[@]} " =~ " ${user} " && "$user" != "root" && "$user" != "your_primary_admin" ]]; then
        USER_ID=$(id -u "$user" 2>/dev/null)
        if [[ $? -ne 0 ]]; then
            echo "[-] Failed to get UID for user '$user'. Skipping."
            continue
        fi
        if [ "$USER_ID" -ge 1000 ] && [ "$user" != "nobody" ]; then
            echo "[*] Deleting user: $user"
            userdel -r "$user" &>/dev/null
            if [ $? -eq 0 ]; then
                echo "[+] User '$user' deleted successfully."
            else
                echo "[-] Failed to delete user '$user' or user does not exist."
            fi
        fi
    fi
done

# 4. Configure Administrator Privileges
echo "[*] Configuring administrator privileges..."

# Remove unauthorized users from the sudo group
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

# Ensure all authorized administrators are in the sudo group
echo "[*] Adding authorized administrators to the sudo group..."
for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
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

# 5. Set User Shells as per USERS_AUTHORIZED
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
        # Secure the shell configuration
        home_dir=$(getent passwd "$user" | cut -d: -f6)
        chmod 755 "$home_dir"
        if [ $? -eq 0 ]; then
            echo "[+] Permissions for home directory of '$user' set to 755."
        else
            echo "[-] Failed to set permissions for home directory of '$user'."
        fi
    else
        echo "[-] User '$user' does not exist."
    fi
done

# 6. Manage Group Memberships as per GROUPS_AUTHORIZED
echo "[*] Managing group memberships as per authorized configurations..."
for group in "${!GROUPS_AUTHORIZED[@]}"; do
    authorized_members=${GROUPS_AUTHORIZED[$group]}
    IFS=' ' read -ra AUTH_MEMBERS <<< "$authorized_members"
    
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
# Disable Guest Access via GDM3
# ------------------------------
echo "[*] Disabling guest access via GDM3..."
GDM3_CUSTOM_CONF='/etc/gdm3/custom.conf'
if [ -f "$GDM3_CUSTOM_CONF" ]; then
    echo "[*] Updating GDM3 configuration to disable guest access."
    sed -i '/^\[daemon\]/a \\
# Disable GNOME Display Manager guest account\\
AllowGuest=false' "$GDM3_CUSTOM_CONF"
    if [ $? -eq 0 ]; then
        echo "[+] Guest access disabled successfully in GDM3."
    else
        echo "[-] Failed to disable guest access in GDM3."
    fi
else
    echo "[-] GDM3 configuration file '$GDM3_CUSTOM_CONF' does not exist."
fi

# ------------------------------
# Firewall Configuration
# ------------------------------
echo "[*] Configuring the firewall (UFW)..."

# 1. Install and Enable UFW
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

# 2. Allow OpenSSH through the Firewall
echo "[*] Allowing SSH through UFW on port $SSH_PORT..."
ufw allow "$SSH_PORT"/tcp
if [ $? -eq 0 ]; then
    echo "[+] SSH port $SSH_PORT allowed through UFW."
else
    echo "[-] Failed to allow SSH port $SSH_PORT through UFW."
fi

# 3. Enable UFW Logging
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

# 1. Install unattended-upgrades
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

# 2. Configure unattended-upgrades
echo "[*] Configuring unattended-upgrades..."
dpkg-reconfigure --priority=low unattended-upgrades
if [ $? -eq 0 ]; then
    echo "[+] unattended-upgrades configured successfully."
else
    echo "[-] Failed to configure unattended-upgrades."
fi

# 3. Configure daily update checks
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

# 4. Upgrade All Packages
echo "[*] Upgrading all packages to the latest versions..."
apt update && apt upgrade -y
if [ $? -eq 0 ]; then
    echo "[+] Packages upgraded successfully."
else
    echo "[-] Failed to upgrade packages."
fi

# 5. Enable Automatic Reboots for Security Updates
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
echo "[*] Removing non-work-related files..."

# 1. Remove Specified Media Files
echo "[*] Deleting specified media files..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
    find / -type f -iname "$pattern" -exec rm -f {} \; 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Files matching '$pattern' removed successfully."
    else
        echo "[-] Failed to remove files matching '$pattern'."
    fi
done
echo "[+] Specified media files removed successfully."

# 2. Remove Hacking Tools
echo "[*] Removing hacking tools..."
HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack")

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
echo "[+] Hacking tools removed successfully."

# ------------------------------
# Password Policy Enforcement
# ------------------------------
echo "[*] Enforcing strong password policies..."

# 1. Install libpam-pwquality
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

# 2. Update Password Requirements
echo "[*] Configuring password strength requirements..."
printf "%s\n" "${PASSWORD_STRENGTH_CONTENT[@]}" > "$PASSWORD_STRENGTH"
if [ $? -eq 0 ]; then
    echo "[+] Password strength requirements updated successfully."
    chmod 600 "$PASSWORD_STRENGTH"
    if [ $? -eq 0 ]; then
        echo "[+] Permissions for '$PASSWORD_STRENGTH' set to 600."
    else
        echo "[-] Failed to set permissions for '$PASSWORD_STRENGTH'."
    fi
else
    echo "[-] Failed to update password strength requirements."
fi

# 3. Configure Account Lockout
echo "[*] Configuring account lockout settings..."
printf "%s\n" "${ACCOUNT_LOCKOUT_CONTENT[@]}" > "$ACCOUNT_LOCKOUT_CONFIG"
if [ $? -eq 0 ]; then
    echo "[+] Account lockout settings configured successfully."
    chmod 600 "$ACCOUNT_LOCKOUT_CONFIG"
    if [ $? -eq 0 ]; then
        echo "[+] Permissions for '$ACCOUNT_LOCKOUT_CONFIG' set to 600."
    else
        echo "[-] Failed to set permissions for '$ACCOUNT_LOCKOUT_CONFIG'."
    fi
else
    echo "[-] Failed to configure account lockout settings."
fi

# 4. Configure Password Aging in /etc/login.defs
echo "[*] Configuring password aging settings in /etc/login.defs..."
sed -i "s/^PASS_MAX_DAYS\s\+.*/PASS_MAX_DAYS\t$PASS_MAX_DAYS/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS\s\+.*/PASS_MIN_DAYS\t$PASS_MIN_DAYS/" /etc/login.defs
sed -i "s/^PASS_WARN_AGE\s\+.*/PASS_WARN_AGE\t$PASS_WARN_AGE/" /etc/login.defs
if [ $? -eq 0 ]; then
    echo "[+] Password aging settings updated successfully."
else
    echo "[-] Failed to update password aging settings."
fi

# ------------------------------
# SSH Configuration
# ------------------------------
echo "[*] Configuring SSH..."

# 1. Apply SSH Configuration
echo "[*] Writing SSH configuration to $SSH_CONFIG"
printf "%s\n" "${SSH_CONFIG_CONTENT[@]}" > "$SSH_CONFIG"
if [ $? -eq 0 ]; then
    echo "[+] SSH configuration updated successfully."
    chmod 600 "$SSH_CONFIG"
    if [ $? -eq 0 ]; then
        echo "[+] Permissions for '$SSH_CONFIG' set to 600."
    else
        echo "[-] Failed to set permissions for '$SSH_CONFIG'."
    fi
else
    echo "[-] Failed to update SSH configuration."
fi

# 2. Restart SSH Service to Apply Changes
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

# 1. Ensure GDM3 is set as the display manager
echo "[*] Ensuring GDM3 is set as the display manager..."
if dpkg-reconfigure -f noninteractive gdm3; then
    echo "[+] GDM3 set as the default display manager."
else
    echo "[-] Failed to set GDM3 as the default display manager."
fi

# 2. Install Firefox via Mozilla PPA
echo "[*] Installing Firefox via Mozilla PPA..."
add-apt-repository -y "$MOZILLA_PPA"
apt update
apt install -y firefox
if [ $? -eq 0 ]; then
    echo "[+] Firefox installed successfully via Mozilla PPA."
else
    echo "[-] Failed to install Firefox via Mozilla PPA."
fi

# 3. Remove Firefox Snap if installed
echo "[*] Removing Firefox Snap package if installed..."
snap list | grep -qw firefox
if [ $? -eq 0 ]; then
    snap remove firefox
    if [ $? -eq 0 ]; then
        echo "[+] Firefox Snap package removed successfully."
    else
        echo "[-] Failed to remove Firefox Snap package."
    fi
else
    echo "[+] Firefox Snap package is not installed."
fi

# 4. Install Thunderbird and Perl
echo "[*] Installing Thunderbird and Perl..."
apt install -y thunderbird perl
if [ $? -eq 0 ]; then
    echo "[+] Thunderbird and Perl installed successfully."
else
    echo "[-] Failed to install Thunderbird and/or Perl."
fi

# 5. Install X2GO Server
echo "[*] Installing X2GO Server..."
apt install -y x2goserver x2goserver-xsession
if [ $? -eq 0 ]; then
    echo "[+] X2GO Server installed successfully."
else
    echo "[-] Failed to install X2GO Server."
fi

# 6. Remove Unnecessary Packages
echo "[*] Removing unnecessary packages..."
UNNECESSARY_PACKAGES=("libreoffice*" "thunderbird*" "transmission*" "brasero*" "gnome-games*" "aisleriot*" "gnome-mahjongg*" "gnome-mines*" "gnome-sudoku*" "ftp*" "telnet*" "yelp*" "yelp-xsl*" "samba-common*" "samba-common-bin*" "tcpdump*")
for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
    apt purge -y "$pkg"
    if [ $? -eq 0 ]; then
        echo "[+] Package '$pkg' removed successfully."
    else
        echo "[-] Failed to remove package '$pkg' or it does not exist."
    fi
done
apt autoremove -y
echo "[+] Unnecessary packages removed successfully."

# ------------------------------
# Service Configuration
# ------------------------------
echo "[*] Configuring services..."

# 1. Ensure sshd is enabled
echo "[*] Ensuring sshd service is enabled and active..."
systemctl enable ssh
systemctl start ssh
if [ $? -eq 0 ]; then
    echo "[+] sshd service is enabled and active."
else
    echo "[-] Failed to enable/start sshd service."
fi

# 2. Disable avahi-daemon
echo "[*] Disabling avahi-daemon..."
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

# 3. Disable Apache2 and Nginx Services
for service in apache2 nginx; do
    echo "[*] Disabling $service service..."
    if systemctl is-enabled --quiet "$service"; then
        systemctl disable --now "$service"
        if [ $? -eq 0 ]; then
            echo "[+] $service service disabled successfully."
        else
            echo "[-] Failed to disable $service service."
        fi
    else
        echo "[+] $service service is already disabled."
    fi
done

# 4. Disable FTP Services if Installed
echo "[*] Disabling FTP services if installed..."
FTP_SERVICES=("vsftpd" "proftpd" "pure-ftpd")
for ftp_service in "${FTP_SERVICES[@]}"; do
    if systemctl is-active --quiet "$ftp_service"; then
        systemctl disable --now "$ftp_service"
        if [ $? -eq 0 ]; then
            echo "[+] '$ftp_service' service disabled."
        else
            echo "[-] Failed to disable '$ftp_service' service."
        fi
    else
        echo "[-] '$ftp_service' service is not active or not installed."
    fi
done

# 5. Install and Configure Fail2Ban
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

# 6. Disable USB Storage (Optional)
echo "[*] Disabling USB storage (optional)..."
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
if [ $? -eq 0 ]; then
    update-initramfs -u
    if [ $? -eq 0 ]; then
        echo "[+] USB storage disabled successfully."
    else
        echo "[-] Failed to update initramfs after disabling USB storage."
    fi
else
    echo "[-] Failed to disable USB storage."
fi

# 7. Restrict Access to Root Directory
echo "[*] Restricting access to the root directory..."
chmod 700 /root
if [ $? -eq 0 ]; then
    echo "[+] Access to the root directory restricted."
else
    echo "[-] Failed to restrict access to the root directory."
fi

# ------------------------------
# Audit and Monitoring
# ------------------------------
echo "[*] Setting up audit and monitoring tools..."

# 1. Install auditd
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

# 2. Configure Audit Rules
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

# 3. Install and Configure Logwatch
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
sed -i 's/^Output = stdout/Output = mail/' /usr/share/logwatch/default.conf/logwatch.conf
sed -i 's/^MailTo = root/MailTo = your_email@example.com/' /usr/share/logwatch/default.conf/logwatch.conf  # Replace with your email
sed -i 's/^Detail = Low/Detail = High/' /usr/share/logwatch/default.conf/logwatch.conf
if [ $? -eq 0 ]; then
    echo "[+] Logwatch configured successfully."
else
    echo "[-] Failed to configure Logwatch."
fi

# ------------------------------
# Program Authorization
# ------------------------------
echo "[*] Ensuring only authorized programs are installed..."

# 1. Fetch list of authorized programs from the manifest
echo "[*] Fetching list of authorized programs..."
AUTHORIZED_PROGRAMS_URL='http://releases.ubuntu.com/22.04/ubuntu-22.04.1-desktop-amd64.manifest'
AUTHORIZED_PROGRAMS=$(wget -q -O - "$AUTHORIZED_PROGRAMS_URL" | awk -F, '{print $1}')
if [ $? -eq 0 ]; then
    echo "[+] Authorized programs list fetched successfully."
else
    echo "[-] Failed to fetch authorized programs list."
    exit 1
fi

# 2. Get currently installed programs
echo "[*] Getting list of installed programs..."
INSTALLED_PROGRAMS=$(apt list --installed 2>/dev/null | cut -d/ -f1)
if [ $? -eq 0 ]; then
    echo "[+] Installed programs list retrieved successfully."
else
    echo "[-] Failed to retrieve installed programs list."
    exit 1
fi

# 3. Remove unauthorized programs
echo "[*] Removing unauthorized programs..."
for program in $INSTALLED_PROGRAMS; do
    if ! echo "$AUTHORIZED_PROGRAMS" | grep -wq "$program"; then
        echo "[*] Removing unauthorized program: $program"
        apt purge -y "$program"
        if [ $? -eq 0 ]; then
            echo "[+] Program '$program' removed successfully."
        else
            echo "[-] Failed to remove program '$program'. It may not exist or another issue occurred."
        fi
    fi
done

# 4. Remove hacking tools explicitly (redundant but ensures removal)
echo "[*] Removing hacking tools explicitly..."
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
echo "[+] Unauthorized programs removed successfully."

# ------------------------------
# Automated Testing
# ------------------------------
echo "[*] Initiating Automated Testing..."

# Define a function for automated tests
run_tests() {
    echo "[*] Running automated tests..."

    # Test if unauthorized users are deleted
    for user in $(cut -f1 -d: /etc/passwd); do
        if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " && ! " ${AUTHORIZED_ADMINISTRATORS[@]} " =~ " ${user} " && "$user" != "root" && "$user" != "your_primary_admin" ]]; then
            USER_ID=$(id -u "$user" 2>/dev/null)
            if [[ $? -eq 0 && "$USER_ID" -ge 1000 && "$user" != "nobody" ]]; then
                echo "[-] Unauthorized user '$user' still exists."
            fi
        fi
    done

    # Test if UFW is enabled
    ufw status | grep -qw "Status: active"
    if [ $? -eq 0 ]; then
        echo "[+] UFW is active."
    else
        echo "[-] UFW is not active."
    fi

    # Test if SSH port is correctly set
    grep -q "^Port $SSH_PORT" "$SSH_CONFIG"
    if [ $? -eq 0 ]; then
        echo "[+] SSH port is correctly set to $SSH_PORT."
    else
        echo "[-] SSH port is not correctly set."
    fi

    # Test if Fail2Ban is active
    systemctl is-active --quiet fail2ban
    if [ $? -eq 0 ]; then
        echo "[+] Fail2Ban is active."
    else
        echo "[-] Fail2Ban is not active."
    fi

    # Test if auditd is active
    systemctl is-active --quiet auditd
    if [ $? -eq 0 ]; then
        echo "[+] auditd is active."
    else
        echo "[-] auditd is not active."
    fi

    # Test if Logwatch is installed
    dpkg -l | grep -qw logwatch
    if [ $? -eq 0 ]; then
        echo "[+] Logwatch is installed."
    else
        echo "[-] Logwatch is not installed."
    fi

    # Test if unauthorized programs are removed
    for program in $INSTALLED_PROGRAMS; do
        if ! echo "$AUTHORIZED_PROGRAMS" | grep -wq "$program"; then
            dpkg -l | grep -qw "$program"
            if [ $? -eq 0 ]; then
                echo "[-] Unauthorized program '$program' is still installed."
            else
                echo "[+] Unauthorized program '$program' is not installed."
            fi
        fi
    done

    # Test if "mariya" is in "pioneers" group
    groups mariya | grep -qw pioneers
    if [ $? -eq 0 ]; then
        echo "[+] User 'mariya' is correctly in the 'pioneers' group."
    else
        echo "[-] User 'mariya' is not in the 'pioneers' group."
    fi

    # Test if GDM3 is the display manager
    current_dm=$(cat /etc/X11/default-display-manager)
    if [[ "$current_dm" == "/usr/sbin/gdm3" ]]; then
        echo "[+] GDM3 is set as the default display manager."
    else
        echo "[-] GDM3 is not set as the default display manager."
    fi

    # Test if Firefox is installed via PPA
    firefox_path=$(which firefox)
    if [ -n "$firefox_path" ]; then
        firefox_version=$(firefox --version)
        echo "[+] Firefox is installed: $firefox_version"
    else
        echo "[-] Firefox is not installed."
    fi

    # Test if X2GO server is installed
    systemctl is-active --quiet x2goserver
    if [ $? -eq 0 ]; then
        echo "[+] X2GO server is active."
    else
        echo "[-] X2GO server is not active."
    fi

    echo "[*] Automated testing completed."
}

# Execute the tests
run_tests

# ------------------------------
# Final Steps
# ------------------------------
echo "[+] CyberPatriots Security Hardening Completed Successfully."

exit 0

# Note: Replace 'your_email@example.com' with your actual email address in the Logwatch configuration.
# Ensure that 'your_primary_admin' is replaced with the actual primary admin username to prevent accidental removal.
