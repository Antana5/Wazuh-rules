# Improved Windows Defender Testing Script
# This script generates events that will trigger Wazuh alerts for Windows Defender disabling
# IMPORTANT: Run this script with administrative privileges
# WARNING: This script temporarily modifies Windows Defender settings for testing purposes

# Function to log actions for easier tracking
function Write-Log {
    param (
        [string]$Message,
        [string]$Type = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Type] $Message"
}

# Function to restore Windows Defender settings
function Restore-DefenderSettings {
    Write-Log "Restoring Windows Defender settings..." "WARN"
    
    # Re-enable Windows Defender Antivirus service
    Write-Log "Re-enabling Windows Defender Antivirus Service..." "INFO"
    Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    
    # Re-enable Real-time protection
    Write-Log "Re-enabling Real-time Protection..." "INFO"
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue

    # Re-enable Security Center service
    Write-Log "Re-enabling Security Center Service..." "INFO"
    Set-Service -Name wscsvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wscsvc -ErrorAction SilentlyContinue

    # Re-enable Windows Defender Firewall service
    Write-Log "Re-enabling Windows Defender Firewall Service..." "INFO"
    Set-Service -Name MpsSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name MpsSvc -ErrorAction SilentlyContinue
    
    # Enable Firewall profiles
    Write-Log "Re-enabling Firewall profiles..." "INFO"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
    
    Write-Log "Windows Defender settings have been restored" "INFO"
}

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "This script requires administrative privileges. Please run as administrator." "ERROR"
    exit 1
}

# Start script with warning
Write-Log "=== Windows Defender Testing Script ===" "WARN"
Write-Log "This script will temporarily disable Windows Defender components to test Wazuh alerts." "WARN"
Write-Log "NOT RECOMMENDED FOR PRODUCTION ENVIRONMENTS!" "WARN"
$confirmation = Read-Host "Do you want to continue? (Y/N)"
if ($confirmation -ne 'Y') {
    Write-Log "Script execution cancelled by user." "INFO"
    exit 0
}

# Save current settings
Write-Log "Saving current settings..." "INFO"
$initialDefenderSettings = @{
    RealTimeMonitoring = (Get-MpPreference).DisableRealtimeMonitoring
    BehaviorMonitoring = (Get-MpPreference).DisableBehaviorMonitoring
    IOAVProtection = (Get-MpPreference).DisableIOAVProtection
    ScriptScanning = (Get-MpPreference).DisableScriptScanning
    WinDefendStatus = (Get-Service -Name WinDefend).Status
    WinDefendStartType = (Get-Service -Name WinDefend).StartType
    WscsvcStatus = (Get-Service -Name wscsvc).Status
    WscsvcStartType = (Get-Service -Name wscsvc).StartType
    MpsSvcStatus = (Get-Service -Name MpsSvc).Status
    MpsSvcStartType = (Get-Service -Name MpsSvc).StartType
    FirewallProfiles = @{}
}

# Save firewall profile states
Get-NetFirewallProfile | ForEach-Object {
    $initialDefenderSettings.FirewallProfiles[$_.Name] = $_.Enabled
}

Write-Log "Current settings backed up. Beginning tests..." "INFO"

try {
    # Register for automatic restoration on script exit
    $null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
        Restore-DefenderSettings
    }

    # Test 1: Disable Real-time Protection (Event ID 5001)
    Write-Log "Test 1: Disabling Real-time Protection..." "TEST"
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    if ((Get-MpPreference).DisableRealtimeMonitoring) {
        Write-Log "Real-time Protection disabled successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to disable Real-time Protection. This might be due to Tamper Protection." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 2: Disable Behavior Monitoring
    Write-Log "Test 2: Disabling Behavior Monitoring..." "TEST"
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    if ((Get-MpPreference).DisableBehaviorMonitoring) {
        Write-Log "Behavior Monitoring disabled successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to disable Behavior Monitoring. This might be due to Tamper Protection." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 3: Disable IOAV Protection
    Write-Log "Test 3: Disabling IOAV Protection..." "TEST"
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    if ((Get-MpPreference).DisableIOAVProtection) {
        Write-Log "IOAV Protection disabled successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to disable IOAV Protection. This might be due to Tamper Protection." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 4: Disable Script Scanning
    Write-Log "Test 4: Disabling Script Scanning..." "TEST"
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    if ((Get-MpPreference).DisableScriptScanning) {
        Write-Log "Script Scanning disabled successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to disable Script Scanning. This might be due to Tamper Protection." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 5: Stop Windows Defender Antivirus Service
    Write-Log "Test 5: Stopping Windows Defender Antivirus Service..." "TEST"
    $defenderServiceResult = Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue -PassThru
    if ($defenderServiceResult -and $defenderServiceResult.Status -eq 'Stopped') {
        Write-Log "Windows Defender Antivirus Service stopped successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to stop Windows Defender Antivirus Service. This might be due to Tamper Protection." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 6: Disable Windows Defender Antivirus Service
    Write-Log "Test 6: Disabling Windows Defender Antivirus Service..." "TEST"
    try {
        Set-Service -Name WinDefend -StartupType Disabled -ErrorAction Stop
        Write-Log "Windows Defender Antivirus Service disabled successfully. Waiting for Wazuh to detect..." "INFO"
    } catch {
        Write-Log "Failed to disable Windows Defender Antivirus Service: $_" "WARN"
    }
    Start-Sleep -Seconds 10
    
    # Test 7: Registry modifications (if possible with Tamper Protection)
    Write-Log "Test 7: Attempting registry modifications (may fail with Tamper Protection)..." "TEST"
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    try {
        Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Log "Registry modification successful. Waiting for Wazuh to detect..." "INFO"
    } catch {
        Write-Log "Failed to modify registry: $_" "WARN"
        Write-Log "This is expected if Tamper Protection is enabled." "INFO"
    }
    Start-Sleep -Seconds 10

    # Test 8: Disable Security Center Service
    Write-Log "Test 8: Stopping Security Center Service..." "TEST"
    $securityCenterResult = Stop-Service -Name wscsvc -Force -ErrorAction SilentlyContinue -PassThru
    if ($securityCenterResult -and $securityCenterResult.Status -eq 'Stopped') {
        Write-Log "Security Center Service stopped successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to stop Security Center Service." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 9: Disable Windows Firewall Service
    Write-Log "Test 9: Stopping Windows Defender Firewall Service..." "TEST"
    $firewallServiceResult = Stop-Service -Name MpsSvc -Force -ErrorAction SilentlyContinue -PassThru
    if ($firewallServiceResult -and $firewallServiceResult.Status -eq 'Stopped') {
        Write-Log "Windows Defender Firewall Service stopped successfully. Waiting for Wazuh to detect..." "INFO"
    } else {
        Write-Log "Failed to stop Windows Defender Firewall Service." "WARN"
    }
    Start-Sleep -Seconds 10

    # Test 10: Disable Windows Firewall Profiles
    Write-Log "Test 10: Disabling Firewall Profiles..." "TEST"
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction Stop
        Write-Log "Firewall profiles disabled successfully. Waiting for Wazuh to detect..." "INFO"
    } catch {
        Write-Log "Failed to disable Firewall profiles: $_" "WARN"
    }
    Start-Sleep -Seconds 10

    Write-Log "All tests completed." "INFO"
}
catch {
    Write-Log "Error occurred: $_" "ERROR"
}
finally {
    # Restore all settings
    Restore-DefenderSettings
    
    # Verify restoration
    $currentDefenderSettings = @{
        RealTimeMonitoring = (Get-MpPreference).DisableRealtimeMonitoring
        BehaviorMonitoring = (Get-MpPreference).DisableBehaviorMonitoring
        IOAVProtection = (Get-MpPreference).DisableIOAVProtection
        ScriptScanning = (Get-MpPreference).DisableScriptScanning
        WinDefendStatus = (Get-Service -Name WinDefend).Status
        WscsvcStatus = (Get-Service -Name wscsvc).Status
        MpsSvcStatus = (Get-Service -Name MpsSvc).Status
    }
    
    $restorationSuccess = $true
    
    # Compare original settings with current settings
    if ($currentDefenderSettings.RealTimeMonitoring -ne $initialDefenderSettings.RealTimeMonitoring) {
        Write-Log "WARNING: Real-time Monitoring was not properly restored." "WARN"
        $restorationSuccess = $false
    }
    
    if ($currentDefenderSettings.WinDefendStatus -ne 'Running') {
        Write-Log "WARNING: Windows Defender service is not running." "WARN"
        $restorationSuccess = $false
    }
    
    if ($currentDefenderSettings.WscsvcStatus -ne 'Running') {
        Write-Log "WARNING: Security Center service is not running." "WARN"
        $restorationSuccess = $false
    }
    
    if ($currentDefenderSettings.MpsSvcStatus -ne 'Running') {
        Write-Log "WARNING: Windows Defender Firewall service is not running." "WARN"
        $restorationSuccess = $false
    }
    
    # Check firewall profiles
    $currentFirewallProfiles = Get-NetFirewallProfile
    foreach ($profile in $currentFirewallProfiles) {
        if (-not $profile.Enabled -and $initialDefenderSettings.FirewallProfiles[$profile.Name]) {
            Write-Log "WARNING: Firewall profile $($profile.Name) was not properly restored." "WARN"
            $restorationSuccess = $false
        }
    }
    
    if ($restorationSuccess) {
        Write-Log "All settings were properly restored to their initial state." "INFO"
    } else {
        Write-Log "Not all settings were properly restored. Manual verification recommended." "WARN"
    }
}

Write-Log "=== Script execution completed ===" "INFO"