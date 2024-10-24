#!/bin/bash

# ==================================================
# CyberPatriots Security Hardening Script for Linux Mint
# Enhanced Version with Improved Security Measures
# ==================================================
# This script performs essential security hardening steps
# required for the CyberPatriots competition.
# ==================================================

# ------------------------------
# Configuration Variables
# ------------------------------

# Logging Configuration
LOGFILE="../cyberpatriots_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Define authorized users (retain these users on the system)
AUTHORIZED_USERS=("root" "your_username")  # Replace 'your_username' with actual usernames

# Define administrators (users with sudo privileges)
ADMINISTRATORS=("root" "admin_username")  # Replace 'admin_username' with actual admin usernames

# Define group authorizations (group: authorized members)
declare -A GROUPS_AUTHORIZED=(
    ["root"]=""
    ["daemon"]=""
    ["bin"]=""
    ["sys"]=""
    ["adm"]="syslog"
    ["tty"]=""
    ["disk"]=""
    ["lp"]=""
    ["mail"]=""
    ["news"]=""
    ["uucp"]=""
    ["man"]=""
    ["proxy"]=""
    ["kmem"]=""
    ["dialout"]=""
    ["fax"]=""
    ["voice"]=""
    ["cdrom"]=""
    ["floppy"]=""
    ["tape"]=""
    ["sudo"]=""
    ["audio"]="pulse"
    ["dip"]=""
    ["www-data"]=""
    ["backup"]=""
    ["operator"]=""
    ["list"]=""
    ["irc"]=""
    ["src"]=""
    ["gnats"]=""
    ["shadow"]=""
    ["utmp"]=""
    ["video"]=""
    ["sasl"]=""
    ["plugdev"]=""
    ["staff"]=""
    ["games"]=""
    ["users"]=""
    ["nogroup"]=""
    ["systemd-journal"]=""
    ["systemd-network"]=""
    ["systemd-resolve"]=""
    ["input"]=""
    ["crontab"]=""
    ["syslog"]=""
    ["messagebus"]=""
    ["netdev"]=""
    ["mlocate"]=""
    ["ssl-cert"]=""
    ["uuidd"]=""
    ["avahi-autoipd"]=""
    ["bluetooth"]=""
    ["rtkit"]=""
    ["ssh"]=""
    ["lpadmin"]=""
    ["whoopsie"]=""
    ["scanner"]="saned"
    ["saned"]=""
    ["pulse"]=""
    ["pulse-access"]=""
    ["avahi"]=""
    ["colord"]=""
    ["geoclue"]=""
    ["gdm"]=""
    ["sambashare"]=""
)

# Define users with specific shells (restrict login capabilities)
declare -A USERS_AUTHORIZED=(
    ["root"]="/bin/false"
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
    ["systemd-network"]="/usr/sbin/nologin"
    ["systemd-resolve"]="/usr/sbin/nologin"
    ["syslog"]="/usr/sbin/nologin"
    ["messagebus"]="/usr/sbin/nologin"
    ["_apt"]="/usr/sbin/nologin"
    ["uuidd"]="/usr/sbin/nologin"
    ["avahi-autoipd"]="/usr/sbin/nologin"
    ["usbmux"]="/usr/sbin/nologin"
    ["dnsmasq"]="/usr/sbin/nologin"
    ["rtkit"]="/usr/sbin/nologin"
    ["speech-dispatcher"]="/bin/false"
    ["whoopsie"]="/bin/false"
    ["kernoops"]="/usr/sbin/nologin"
    ["saned"]="/usr/sbin/nologin"
    ["pulse"]="/usr/sbin/nologin"
    ["avahi"]="/usr/sbin/nologin"
    ["colord"]="/usr/sbin/nologin"
    ["hplip"]="/bin/false"
    ["geoclue"]="/usr/sbin/nologin"
    ["gnome-initial-setup"]="/bin/false"
    ["gdm"]="/bin/false"
)

# Disable guest access via LightDM
GUEST_CONFIG='/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf'
GUEST_FILE_CONTENT=(
    "[Seat:*]"
    "user-session=ubuntu"
    "allow-guest=false"
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
    "UsePAM yes"
    "X11Forwarding yes"
    "PrintMotd no"
    "AcceptEnv LANG LC_*"
    "Subsystem\tsftp\t/usr/lib/openssh/sftp-server"
    "ChallengeResponseAuthentication no"
)

# Programs Authorization
AUTHORIZED_PROGRAMS_URL='http://releases.ubuntu.com/18.04/ubuntu-18.04.1-desktop-amd64.manifest'
PROGRAMS_COMMAND='apt list --installed | cut -d/ -f1'
ADD_PROGRAM_COMMAND=('apt' 'install')
REMOVE_PROGRAM_COMMAND=('apt' 'purge')

# File Types to Remove
FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")

# ------------------------------
# Ensure the script is run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Use sudo." 
   exit 1
fi

echo "[+] Starting CyberPatriots Security Hardening Script..."

# ------------------------------
# User and Permissions Management
# ------------------------------
echo "[*] Managing users and permissions..."

# 1. Delete Unauthorized Users
echo "[*] Deleting unauthorized users..."
for user in $(cut -f1 -d: /etc/passwd); do
    if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
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
        # Secure the shell configuration
        chmod 755 "$(getent passwd "$user" | cut -d: -f6)"
        if [ $? -eq 0 ]; then
            echo "[+] Permissions for home directory of '$user' set to 755."
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
# Disable Guest Access via LightDM
# ------------------------------
echo "[*] Disabling guest access via LightDM..."
if [ -f "$GUEST_CONFIG" ]; then
    echo "[*] Writing guest configuration to $GUEST_CONFIG"
    printf "%s\n" "${GUEST_FILE_CONTENT[@]}" > "$GUEST_CONFIG"
    if [ $? -eq 0 ]; then
        echo "[+] Guest access disabled successfully."
    else
        echo "[-] Failed to disable guest access."
    fi
else
    echo "[-] Guest configuration file '$GUEST_CONFIG' does not exist."
fi

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

# 6. Allow OpenSSH through the Firewall
echo "[*] Allowing OpenSSH through UFW..."
ufw allow OpenSSH
if [ $? -eq 0 ]; then
    echo "[+] OpenSSH allowed through UFW."
else
    echo "[-] Failed to allow OpenSSH through UFW."
fi

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
echo "[*] Removing non-work-related files..."

# 11. Remove Specified Media Files
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

# 13. Configure Account Lockout
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

# 14. Configure Password Aging in /etc/login.defs
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

# 15. Apply SSH Configuration
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

# 16. Restart SSH Service to Apply Changes
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

# 17. Delete ophcrack
echo "[*] Removing ophcrack..."
if dpkg -l | grep -qw ophcrack; then
    apt remove --purge -y ophcrack
    apt autoremove -y
    if [ $? -eq 0 ]; then
        echo "[+] ophcrack removed successfully."
    else
        echo "[-] Failed to remove ophcrack."
    fi
else
    echo "[+] ophcrack is not installed."
fi

# 18. Remove Unnecessary Packages
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

# 19. Disable avahi-daemon
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

# 20. Disable Apache2 Service
echo "[*] Disabling Apache2 service..."
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

# 21. Disable Nginx Service
echo "[*] Disabling Nginx service..."
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

# 22. Disable FTP Services if Installed
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

# 23. Install and Configure Fail2Ban
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

# 24. Disable USB Storage (Optional)
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

# 25. Restrict Access to Root Directory
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

# 26. Install and Configure Auditd
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

# 27. Configure Audit Rules
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

# 28. Install and Configure Logwatch
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

# 29. Fetch list of authorized programs from the manifest
echo "[*] Fetching list of authorized programs..."
AUTHORIZED_PROGRAMS=$(wget -q -O - "$AUTHORIZED_PROGRAMS_URL" | awk -F, '{print $1}')
if [ $? -eq 0 ]; then
    echo "[+] Authorized programs list fetched successfully."
else
    echo "[-] Failed to fetch authorized programs list."
    exit 1
fi

# 30. Get currently installed programs
echo "[*] Getting list of installed programs..."
INSTALLED_PROGRAMS=$(apt list --installed 2>/dev/null | cut -d/ -f1)
if [ $? -eq 0 ]; then
    echo "[+] Installed programs list retrieved successfully."
else
    echo "[-] Failed to retrieve installed programs list."
    exit 1
fi

# 31. Remove unauthorized programs
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
        if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
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

    echo "[*] Automated testing completed."
}

# Execute the tests
run_tests

# ------------------------------
# Final Steps
# ------------------------------
echo "[+] CyberPatriots Security Hardening Completed Successfully."

exit 0