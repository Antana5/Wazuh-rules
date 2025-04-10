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
        
        # Try to check why the service might fail before restarting
        if [[ "$service_name" == "wazuh-manager" ]]; then
            logger "Checking Wazuh configuration..."
            /var/ossec/bin/wazuh-logtest-legacy -t > /tmp/wazuh_config_check.log 2>&1
            if [[ $? -ne 0 ]]; then
                logger -e "Wazuh configuration test failed. See /tmp/wazuh_config_check.log for details."
                cat /tmp/wazuh_config_check.log
                return 1
            else
                logger "Wazuh configuration test passed."
            fi
        fi
        
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
        logger -e "${service_name^} could not be restarted. Checking logs..."
        
        # Display last 20 lines of log for debugging
        if [[ -f "/var/ossec/logs/ossec.log" ]]; then
            logger "Last 20 lines of /var/ossec/logs/ossec.log:"
            tail -n 20 /var/ossec/logs/ossec.log
        fi
        
        # Check for systemd journal logs
        if systemctl --version &>/dev/null; then
            logger "Systemd journal for $service_name:"
            journalctl -u "$service_name.service" -n 20 --no-pager
        fi
        
        return 1
    else
        logger "${service_name^} restarted successfully"
        return 0
    fi
}

# Restore backup rules in case of failure
restore_backup() {
    logger -e "Attempting to restore backed up rules..."
    
    # Stop the service first to avoid restart failures
    if systemctl --version &>/dev/null; then
        systemctl stop wazuh-manager.service
    elif service --version &>/dev/null; then
        service wazuh-manager stop
    fi
    
    # Restore original rules
    \cp -rf /tmp/wazuh_rules_backup/* /var/ossec/etc/rules/
    chown wazuh:wazuh /var/ossec/etc/rules/*
    chmod 660 /var/ossec/etc/rules/*
    
    # Restore original decoders if they were backed up
    if [[ -d "/tmp/wazuh_decoders_backup" && -n "$(ls -A /tmp/wazuh_decoders_backup)" ]]; then
        \cp -rf /tmp/wazuh_decoders_backup/* /var/ossec/etc/decoders/
        chown wazuh:wazuh /var/ossec/etc/decoders/*
        chmod 660 /var/ossec/etc/decoders/*
    fi
    
    # Try to validate configuration before restarting
    logger "Validating configuration after restore..."
    /var/ossec/bin/wazuh-logtest-legacy -t
    
    # Restart service
    restart_service "wazuh-manager"
    
    # Clean up
    rm -rf /tmp/Antana5-Wazuh-Rules
}

# Validate XML files
validate_xml_files() {
    local error_found=false
    local xmllint_available=false
    
    # Check if xmllint is available
    if command -v xmllint &>/dev/null; then
        xmllint_available=true
    else
        logger -w "xmllint not found. Skipping XML validation. Consider installing libxml2-utils for better error detection."
        return 0
    fi
    
    if [[ "$xmllint_available" == "true" ]]; then
        logger "Validating XML files..."
        
        # Check rules
        for xml_file in /var/ossec/etc/rules/*.xml; do
            if ! xmllint --noout "$xml_file" 2>/dev/null; then
                logger -e "XML validation failed for $xml_file"
                xmllint --noout "$xml_file"
                error_found=true
            fi
        done
        
        # Check decoders
        for xml_file in /var/ossec/etc/decoders/*.xml; do
            if ! xmllint --noout "$xml_file" 2>/dev/null; then
                logger -e "XML validation failed for $xml_file"
                xmllint --noout "$xml_file"
                error_found=true
            fi
        done
    fi
    
    if [[ "$error_found" == "true" ]]; then
        logger -e "XML validation errors found. This may cause Wazuh to fail starting."
        return 1
    fi
    
    return 0
}

# Perform health check on Wazuh manager
health_check() {
    logger "Performing a health check"
    cd /var/ossec || exit 1
    restart_service "wazuh-manager"
    
    # If restart failed, no need to continue
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    # Wait for service to fully start
    logger "Waiting for Wazuh manager to initialize (20 seconds)..."
    sleep 20
    
    # Check if wazuh-manager is running
    if ! ps -ef | grep -v grep | grep -q "wazuh-manager"; then
        logger -e "Wazuh-Manager process is not running after restart."
        return 1
    fi
    
    # Check specific components
    if [[ -n "$(/var/ossec/bin/wazuh-control status | grep 'not running')" ]]; then
        logger -e "Some Wazuh components are not running:"
        /var/ossec/bin/wazuh-control status | grep 'not running'
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
    
    # Backup existing decoders
    if [[ -d "$decoder_dir" && -n "$(ls -A "$decoder_dir" 2>/dev/null)" ]]; then
        mkdir -p /tmp/wazuh_decoders_backup
        logger "Backing up current decoders into /tmp/wazuh_decoders_backup/"
        \cp -r "$decoder_dir"/* /tmp/wazuh_decoders_backup/
    fi
    
    # Ensure the decoders directory exists
    if [[ ! -d "$decoder_dir" ]]; then
        logger "Creating decoders directory"
        mkdir -p "$decoder_dir"
    fi
    
    # Find and move all decoder files
    logger "Moving decoder files to $decoder_dir"
    find_result=$(find /tmp/Antana5-Wazuh-Rules -name '*_decoders.xml' 2>/dev/null)
    
    if [[ -z "$find_result" ]]; then
        logger -w "No decoder files found in repository. Checking for other naming patterns..."
        find_result=$(find /tmp/Antana5-Wazuh-Rules -name '*decoder*.xml' 2>/dev/null)
    fi
    
    if [[ -n "$find_result" ]]; then
        echo "$find_result" | while read -r decoder_file; do
            cp "$decoder_file" "$decoder_dir/"
            logger "Copied $(basename "$decoder_file") to decoders directory"
        done
    else
        logger -w "No decoder files found in repository."
    fi
    
    # Set permissions
    if [[ -n "$(ls -A "$decoder_dir" 2>/dev/null)" ]]; then
        chown -R wazuh:wazuh "$decoder_dir"
        chmod -R 660 "$decoder_dir"/*
        logger "Decoders moved to $decoder_dir with proper permissions"
    fi
}

# Function to check logcollector status
check_logcollector() {
    local max_attempts=3
    local attempt=1
    local status
    
    while [[ $attempt -le $max_attempts ]]; do
        status=$(/var/ossec/bin/wazuh-control status | grep 'wazuh-logcollector')
        
        if [[ "$status" == *"running"* ]]; then
            logger "Logcollector is running properly"
            return 0
        else
            logger -w "Logcollector not running on attempt $attempt of $max_attempts"
            
            if [[ $attempt -lt $max_attempts ]]; then
                logger "Waiting 30 seconds before checking again..."
                sleep 30
            fi
            
            attempt=$((attempt + 1))
        fi
    done
    
    logger -e "Logcollector failed to start after $max_attempts attempts"
    return 1
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
    \cp -r /var/ossec/etc/rules/* /tmp/wazuh_rules_backup/ 2>/dev/null || true
    
    # Clone repository
    logger "Cloning Antana5's Wazuh Rules repository..."
    if ! git clone https://github.com/Antana5/Wazuh-rules.git /tmp/Antana5-Wazuh-Rules; then
        logger -e "Failed to clone Antana5's rules repository"
        return 1
    fi
    
    # Move to main branch if not already on it
    cd /tmp/Antana5-Wazuh-Rules || return 1
    git checkout main
    
    # Check if we actually have rule files
    if [[ -z "$(find . -name '*.xml' 2>/dev/null)" ]]; then
        logger -e "No XML files found in the repository. Aborting installation."
        return 1
    fi
    
    # List all rule files for debugging
    logger "Found the following rule files in repository:"
    find . -name '*.xml' | sort
    
    # Move rules to appropriate directory
    logger "Copying rule files to /var/ossec/etc/rules/"
    find . -name '*.xml' -not -name '*_decoders.xml' -not -name '*decoder*.xml' -exec cp {} /var/ossec/etc/rules/ \;
    
    # Move decoders to appropriate directory
    move_decoders
    
    # Save version info
    /var/ossec/bin/wazuh-control info 2>&1 | tee /tmp/version.txt
    
    # Set permissions for rules directory
    logger "Setting correct permissions for rule files"
    chown -R wazuh:wazuh /var/ossec/etc/rules/
    chmod -R 660 /var/ossec/etc/rules/*.xml
    
    # Validate configuration
    logger "Validating Wazuh rules and decoders"
    validate_xml_files
    
    # Test configuration
    logger "Testing Wazuh configuration"
    /var/ossec/bin/wazuh-logtest-legacy -t
    local config_test_result=$?
    
    if [[ $config_test_result -ne 0 ]]; then
        logger -e "Wazuh configuration test failed. Reverting changes."
        restore_backup
        return 1
    fi
    
    # Restart service
    logger "Rules downloaded, attempting to restart the Wazuh-Manager service"
    if ! restart_service "wazuh-manager"; then
        logger -e "Failed to restart Wazuh manager. Reverting changes."
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
    
    # Check for wazuh-logtest-legacy tool
    if [[ ! -x "/var/ossec/bin/wazuh-logtest-legacy" ]]; then
        logger -w "wazuh-logtest-legacy tool not found. This may be due to a different Wazuh version."
        logger -w "Configuration validation will be limited."
    fi
    
    # Determine package manager
    SYS_TYPE=$(detect_package_manager)
    
    # Banner
    echo "========================================================"
    echo "  Antana5 Wazuh Rules Installer"
    echo "  https://github.com/Antana5/Wazuh-rules"
    echo "========================================================"
    echo ""
    
    # Display Wazuh version
    if [[ -x "/var/ossec/bin/wazuh-control" ]]; then
        echo "Detected Wazuh version:"
        /var/ossec/bin/wazuh-control info | grep "WAZUH_VERSION\|WAZUH_REVISION"
        echo ""
    fi
    
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
    if clone_rules && health_check; then
        logger "Installation process completed successfully"
        exit 0
    else
        logger -e "Installation process failed"
        exit 1
    fi
}

# Run the main function
main "$@"