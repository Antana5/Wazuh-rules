#!/bin/bash
# Simplified script to install Wazuh rules from the Antana5 repository

# Set path for command execution
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Logger function for output
logger() {
    local now=$(date +'%m/%d/%Y %H:%M:%S')
    local mtype="INFO:"
    local message="$1"
    
    if [[ "$1" == "-e" ]]; then
        mtype="ERROR:"
        message="$2"
    elif [[ "$1" == "-w" ]]; then
        mtype="WARNING:"
        message="$2"
    fi
    
    echo "$now $mtype $message"
}

# Main installation function
install_rules() {
    # Create destination directories if they don't exist
    mkdir -p /var/ossec/etc/rules
    mkdir -p /var/ossec/etc/decoders
    mkdir -p /var/ossec/etc/shared/default
    
    # Clean up any previous clones
    rm -rf /tmp/Wazuh-rules-test
    
    # Clone the repository to a known location
    logger "Cloning repository..."
    if ! git clone https://github.com/Antana5/Wazuh-rules.git /tmp/Wazuh-rules-test; then
        logger -e "Failed to clone repository"
        exit 1
    fi
    
    cd /tmp/Wazuh-rules-test/Wazuh-Rules-main || {
        logger -e "Failed to find Wazuh-Rules-main directory"
        exit 1
    }
    
    # Get the actual directory list from the repository
    logger "Finding rule directories..."
    mapfile -t actual_dirs < <(find . -maxdepth 1 -type d | grep -v "^\.$" | sort)
    
    # Display found directories
    logger "Found these directories in the repository:"
    for dir in "${actual_dirs[@]}"; do
        logger "  - ${dir#./}"
    done
    
    # Process each directory found
    for dir in "${actual_dirs[@]}"; do
        dir_name="${dir#./}"
        if [[ -n "$dir_name" ]]; then
            logger "Processing directory: $dir_name"
            
            # Find and copy XML files
            xml_files=$(find "$dir" -name "*.xml" 2>/dev/null)
            if [[ -n "$xml_files" ]]; then
                logger "  Copying XML files from $dir_name"
                find "$dir" -name "*.xml" -exec cp {} /var/ossec/etc/rules/ \;
            else
                logger "  No XML files found in $dir_name"
            fi
            
            # Check for agent.conf
            if [[ -f "$dir/agent.conf" ]]; then
                logger "  Found agent.conf in $dir_name - copying to shared/default"
                cp "$dir/agent.conf" /var/ossec/etc/shared/default/
            fi
        fi
    done
    
    # Also copy any XML files in the root directory
    logger "Checking for XML files in the root directory..."
    xml_files_root=$(find . -maxdepth 1 -name "*.xml" 2>/dev/null)
    if [[ -n "$xml_files_root" ]]; then
        logger "Copying XML files from root directory"
        find . -maxdepth 1 -name "*.xml" -exec cp {} /var/ossec/etc/rules/ \;
    else
        logger "No XML files found in root directory"
    fi
    
    # Move specific decoder files to the decoders directory
    logger "Moving decoder files to the decoders directory..."
    decoders=(
        "decoder-linux-sysmon.xml"
        "yara_decoders.xml"
        "auditd_decoders.xml"
        "naxsi-opnsense_decoders.xml"
        "maltrail_decoders.xml"
        "decoder-manager-logs.xml"
    )
    
    for decoder in "${decoders[@]}"; do
        if [[ -f "/var/ossec/etc/rules/$decoder" ]]; then
            logger "Moving decoder $decoder to decoders directory"
            mv "/var/ossec/etc/rules/$decoder" "/var/ossec/etc/decoders/"
        fi
    done
    
    # Set proper ownership and permissions
    logger "Setting ownership and permissions..."
    chown -R wazuh:wazuh /var/ossec/etc/rules/* 2>/dev/null || true
    chmod -R 660 /var/ossec/etc/rules/* 2>/dev/null || true
    
    if [[ -f /var/ossec/etc/shared/default/agent.conf ]]; then
        chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf 2>/dev/null || true
        chmod 660 /var/ossec/etc/shared/default/agent.conf 2>/dev/null || true
    fi
    
    # List installed rules
    logger "Installed rules:"
    ls -la /var/ossec/etc/rules/
    
    logger "Installation complete!"
    logger "Note: You need to restart the Wazuh manager manually for the changes to take effect:"
    logger "  systemctl restart wazuh-manager"
}

# Main execution
echo "This script will install Wazuh rules from the Antana5/Wazuh-rules repository."
read -p "Do you want to continue? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    install_rules
else
    echo "Installation cancelled."
fi