#!/bin/bash

# ==================================================
# User and Password Policy Management Script for Linux Mint
# ==================================================
# This script performs the following tasks:
# - Removes unauthorized users.
# - Assigns administrators to the sudo group.
# - Removes unauthorized users from the sudo group.
# - Upgrades password policies.
# ==================================================

# ------------------------------
# Ensure the script is run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root. Use sudo."
   exit 1
fi

echo "[+] Starting User and Password Policy Management Script..."

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
MIN_PASS_LENGTH=12        # Set minimum password length
MAX_PASS_LENGTH=24        # Set maximum password length
PASSWORD_COMPLEXITY="ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"  # Define password complexity

# Password Expiration Settings
PASS_MAX_DAYS=90           # Maximum number of days a password can be used
PASS_MIN_DAYS=10           # Minimum number of days between password changes
PASS_WARN_AGE=7            # Days before password expiration to warn the user

# Password Strength Configuration
PASSWORD_STRENGTH='/etc/pam.d/common-password'

# ------------------------------
# User Management
# ------------------------------
echo "[*] Managing users..."

# 1. Remove Unauthorized Users
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
# Final Steps
# ------------------------------
echo "[+] User and Password Policy Management Completed Successfully."

exit 0
