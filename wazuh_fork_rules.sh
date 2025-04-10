#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Default configuration
SKIP_CONFIRMATION=false
DEBUG=false

# Function to print usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Configure Wazuh with Antana5's ruleset"
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
    rm -rf /tmp/Antana5-Wazuh-Rules
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
        logger "Wazuh-Manager Service is healthy. Installation successful!"
        logger "Enjoy your enhanced Wazuh rules from Antana5."
        rm -rf /tmp/Antana5-Wazuh-Rules
        return 0
    fi
}

# Move decoder files to appropriate location
move_decoders() {
    local decoder_dir="/var/ossec/etc/decoders"
    
    # Ensure the decoders directory exists
    if [[ ! -d "$decoder_dir" ]]; then
        logger "Creating decoders directory"
        mkdir -p "$decoder_dir"
        chown wazuh:wazuh "$decoder_dir"
        chmod 750 "$decoder_dir"
    fi
    
    # Find and move all decoder files
    find /tmp/Antana5-Wazuh-Rules -name '*_decoders.xml' -exec mv {} "$decoder_dir/" \;
    
    # Set permissions
    if [[ -n "$(ls -A "$decoder_dir")" ]]; then
        chown wazuh:wazuh "$decoder_dir"/*
        chmod 660 "$decoder_dir"/*
        logger "Decoders moved to $decoder_dir"
    fi
}

# Clone and install Antana5 rules
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
    if ! git clone https://github.com/Antana5/Wazuh-rules.git /tmp/Antana5-Wazuh-Rules; then
        logger -e "Failed to clone Antana5's rules repository"
        return 1
    fi
    
    # Move to main branch if not already on it
    cd /tmp/Antana5-Wazuh-Rules || return 1
    git checkout main
    
    # Move rules to appropriate directory
    find . -name '*.xml' -not -name '*_decoders.xml' -exec cp {} /var/ossec/etc/rules/ \;
    
    # Move decoders to appropriate directory
    move_decoders
    
    # Save version info
    /var/ossec/bin/wazuh-control info 2>&1 | tee /tmp/version.txt
    
    # Set permissions
    chown wazuh:wazuh /var/ossec/etc/rules/*
    chmod 660 /var/ossec/etc/rules/*
    
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
    
    # Banner
    echo "========================================================"
    echo "  Antana5 Wazuh Rules Installer"
    echo "  https://github.com/Antana5/Wazuh-rules"
    echo "========================================================"
    echo ""
    
    # Confirmation prompt unless skipped
    if [[ "$SKIP_CONFIRMATION" != "true" ]]; then
        while true; do
            read -p "Do you wish to configure Wazuh with Antana5's ruleset? WARNING - This script will replace all of your current custom Wazuh Rules. Please proceed with caution and it is recommended to manually back up your rules... continue? (y/n) " yn
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