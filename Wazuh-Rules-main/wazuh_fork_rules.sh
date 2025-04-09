#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Default configuration
SKIP_CONFIRMATION=false
DEBUG=false

# Function to print usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Configure Wazuh with SOCFortress ruleset"
    echo ""
    echo "Options:"
    echo "  -y, --yes         Skip confirmation prompt"
    echo "  -d, --debug       Enable debug output"
    echo "  -h, --help        Display this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            SKIP_CONFIRMATION=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Set debug output if enabled
[[ "$DEBUG" == true ]] && debug="--debug" || debug=""

# Logger function for consistent output formatting
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

# Determine package manager
detect_package_manager() {
    if command -v yum &>/dev/null; then
        echo "yum"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    elif command -v apt-get &>/dev/null; then
        echo "apt-get"
    else
        logger -e "Unable to determine package manager. Exiting."
        exit 1
    fi
}

# Check for required dependencies
check_dependencies() {
    if ! command -v git &>/dev/null; then
        logger -e "git package could not be found. Please install with $(SYS_TYPE) install git."
        exit 1
    fi
    logger "Git package found. Continuing..."
}

# Check system architecture
check_architecture() {
    if [[ "$(uname -m)" != "x86_64" ]]; then
        logger -e "Incompatible system. This script must be run on a 64-bit system."
        exit 1
    fi
}

# Restart service with appropriate method
restart_service() {
    local service_name="$1"
    
    if systemctl --version &>/dev/null; then
        logger "Restarting $service_name using systemd..."
        systemctl restart "$service_name.service" ${debug}
    elif service --version &>/dev/null; then
        logger "Restarting $service_name using service..."
        service "$service_name" restart ${debug}
    elif [[ -x "/etc/rc.d/init.d/$service_name" ]]; then
        logger "Restarting $service_name using init script..."
        "/etc/rc.d/init.d/$service_name" start ${debug}
    else
        logger -e "${service_name^} could not restart. No service manager found on the system."
        return 1
    fi
    
    # Check restart status
    if [[ $? -ne 0 ]]; then
        logger -e "${service_name^} could not be restarted. Please check /var/ossec/logs/ossec.log for details."
        return 1
    else
        logger "${service_name^} restarted successfully"
        return 0
    fi
}

# Restore backup rules in case of failure
restore_backup() {
    logger -e "Attempting to restore backed up rules..."
    \cp -r /tmp/wazuh_rules_backup/* /var/ossec/etc/rules/
    chown wazuh:wazuh /var/ossec/etc/rules/*
    chmod 660 /var/ossec/etc/rules/*
    restart_service "wazuh-manager"
    rm -rf /tmp/Wazuh-Rules
}

# Perform health check on Wazuh manager
health_check() {
    logger "Performing a health check"
    cd /var/ossec || exit 1
    restart_service "wazuh-manager"
    
    # Wait for service to fully start
    sleep 20
    
    if [[ -n "$(/var/ossec/bin/wazuh-control status | grep 'wazuh-logcollector not running...')" ]]; then
        logger -e "Wazuh-Manager Service is not healthy. Please check /var/ossec/logs/ossec.log for details."
        return 1
    else
        logger "Wazuh-Manager Service is healthy. Thanks for checking us out :)"
        logger "Get started with our free-for-life tier here: https://www.socfortress.co/trial.html Happy Defending!"
        rm -rf /tmp/Wazuh-Rules
        return 0
    fi
}

# Move decoder files to appropriate location
move_decoders() {
    local decoders=(
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
}

# Clone and install SOCFortress rules
clone_rules() {
    logger "Beginning the installation process"
    
    # Check if Wazuh manager is installed
    local is_installed=false
    case "$SYS_TYPE" in
        yum|zypper)
            rpm -qa | grep -q wazuh-manager && is_installed=true
            ;;
        apt-get)
            apt list --installed 2>/dev/null | grep -q wazuh-manager && is_installed=true
            ;;
    esac
    
    if [[ "$is_installed" != "true" ]]; then
        logger -e "Wazuh-Manager software could not be found or is not installed"
        return 1
    fi
    
    # Backup existing rules
    mkdir -p /tmp/wazuh_rules_backup
    logger "Backing up current rules into /tmp/wazuh_rules_backup/"
    \cp -r /var/ossec/etc/rules/* /tmp/wazuh_rules_backup/
    
    # Clone and install new rules
    if ! git clone https://github.com/socfortress/Wazuh-Rules.git /tmp/Wazuh-Rules; then
        logger -e "Failed to clone SOCFortress rules repository"
        return 1
    fi
    
    cd /tmp/Wazuh-Rules || return 1
    
    # Install rule files from the new directory structure
    logger "Installing rules from structured directories..."
    
    # List of rule directories
    rule_dirs=(
    "Exclusion Rules"
    "Healthcheck"
    "lsaas_dump_100430-100443"  # This is the correct directory name
    "PEAKLIGHT_100601-100611"   # This is the correct directory name
    "powershell_100201-100206"  # This is the correct directory name
    "SOCFortress"
    "Software"
    "Sysmon New Events"
    "Wazuh Inventory"
    "Windows Autoruns"
    "Windows Logon Sessions"
    "Windows Powershell"
    "Windows_defender_tampering_110003-110008"  # This is the correct directory name
    "Windows_Sysmon"
)
    
    # Process each rule directory
    for dir in "${rule_dirs[@]}"; do
        # Check if directory exists
        if [[ -d "/tmp/Wazuh-Rules/${dir}" ]]; then
            logger "Processing rules from directory: ${dir}"
            find "/tmp/Wazuh-Rules/${dir}" -name '*.xml' -exec cp {} /var/ossec/etc/rules/ \;
        else
            logger -w "Directory not found: ${dir}"
        fi
    done
    
    # Also check for any XML files in the root directory
    find /tmp/Wazuh-Rules -maxdepth 1 -name '*.xml' -exec cp {} /var/ossec/etc/rules/ \;
    
    # Move decoders to appropriate directory
    move_decoders
    
    # Save version info
    /var/ossec/bin/wazuh-control info 2>&1 | tee /tmp/version.txt
    
    # Set permissions
    chown wazuh:wazuh /var/ossec/etc/rules/*
    chmod 660 /var/ossec/etc/rules/*
    
    # Copy any agent.conf files from rule directories to the repository
    logger "Checking for agent configuration files..."
    for dir in "${rule_dirs[@]}"; do
        if [[ -f "/tmp/Wazuh-Rules/${dir}/agent.conf" ]]; then
            logger "Found agent.conf in ${dir} - copying to /var/ossec/etc/shared/default"
            mkdir -p /var/ossec/etc/shared/default
            cp "/tmp/Wazuh-Rules/${dir}/agent.conf" /var/ossec/etc/shared/default/
            chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf
            chmod 660 /var/ossec/etc/shared/default/agent.conf
        fi
    done
    
    # Restart service
    logger "Rules downloaded, attempting to restart the Wazuh-Manager service"
    if ! restart_service "wazuh-manager"; then
        restore_backup
        return 1
    fi
    
    return 0
}

# Main function
main() {
    clear
    
    # Check if running as root
    if [[ "$EUID" -ne 0 ]]; then
        logger -e "This script must be run as root."
        exit 1
    fi
    
    # Determine package manager
    SYS_TYPE=$(detect_package_manager)
    
    # Confirmation prompt unless skipped
    if [[ "$SKIP_CONFIRMATION" != "true" ]]; then
        while true; do
            read -p "Do you wish to configure Wazuh with the SOCFortress FORK ruleset? WARNING - This script will replace all of your current custom Wazuh Rules. Please proceed with caution and it is recommended to manually back up your rules... continue? (y/n) " yn
            case $yn in
                [Yy]* ) break;;
                [Nn]* ) exit;;
                * ) echo "Please answer yes or no.";;
            esac
        done
    else
        logger "Confirmation skipped with -y flag"
    fi
    
    # Run installation
    check_dependencies
    check_architecture
    clone_rules
    health_check
    
    logger "Installation process completed"
}

# Run the main function
main "$@"