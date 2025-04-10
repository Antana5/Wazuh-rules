# PowerShell Detection Rules Test Script
# ⚠️ FOR TESTING ONLY - This script simulates suspicious PowerShell behaviors ⚠️
# This script tests rules 100201-100206 for PowerShell security detection

function Initialize-TestEnvironment {
    $testFolder = "$env:TEMP\PsDetectionTest"
    if (-not (Test-Path -Path $testFolder)) {
        New-Item -Path $testFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created test directory: $testFolder" -ForegroundColor Gray
    }
    
    Write-Host "`n===================================================" -ForegroundColor Magenta
    Write-Host "PowerShell DETECTION TESTS" -ForegroundColor Magenta
    Write-Host "===================================================" -ForegroundColor Magenta
    Write-Host "This script simulates suspicious PowerShell behaviors." -ForegroundColor Yellow
    Write-Host "No actual malicious activity will be performed." -ForegroundColor Yellow
    Write-Host "Tests will create logs that Wazuh and Sysmon can detect." -ForegroundColor Yellow
    Write-Host "===================================================" -ForegroundColor Magenta
    
    return $testFolder
}

function Test-EncodedCommand {
    param (
        [string]$TestFolder
    )
    
    Write-Host "`n[TEST 1] Encoded PowerShell Commands (Rule 100201)" -ForegroundColor Cyan
    Write-Host "------------------------------------------------" -ForegroundColor Cyan
    
    # Create a harmless command to encode
    $harmlessCommand = "Write-Host 'This is a test of encoded command detection'"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($harmlessCommand)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    
    # Log the encoded command pattern
    $commandLog = @"
This is a simulated PowerShell transcript showing encoded command usage:

CommandInvocation(powershell.exe): "powershell.exe -EncodedCommand $encodedCommand"

The above is a harmless test command that would display a message.
"@
    
    $encodedCommandLogPath = "$TestFolder\encoded_command_test.log"
    $commandLog | Out-File -FilePath $encodedCommandLogPath
    Write-Host "Created encoded command log at: $encodedCommandLogPath" -ForegroundColor Green
    
    # Simulate the FromBase64String pattern
    $fromBase64Log = @"
PowerShell executed code: [System.Convert]::FromBase64String('SGFybWxlc3MgdGVzdCBzdHJpbmc=')
"@
    $fromBase64LogPath = "$TestFolder\from_base64_test.log"
    $fromBase64Log | Out-File -FilePath $fromBase64LogPath
    Write-Host "Created FromBase64String log at: $fromBase64LogPath" -ForegroundColor Green
    
    # Write a harmless script that uses a technique that might trigger the rule
    $testScriptPath = "$TestFolder\encoded_test.ps1"
    @"
# This is a test script that uses encoding techniques
# It's completely harmless but contains patterns that security tools might flag

# Encoding a simple string
`$harmlessString = "This is a test string"
`$bytes = [System.Text.Encoding]::Unicode.GetBytes(`$harmlessString)
`$encodedText = [Convert]::ToBase64String(`$bytes)
Write-Host "Encoded: `$encodedText"

# Decoding the string
`$decodedBytes = [Convert]::FromBase64String(`$encodedText)
`$decodedText = [System.Text.Encoding]::Unicode.GetString(`$decodedBytes)
Write-Host "Decoded: `$decodedText"
"@ | Out-File -FilePath $testScriptPath
    
    Write-Host "Created test script at: $testScriptPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100201" -ForegroundColor Yellow
    Write-Host "NOTE: For accurate testing, run the following command in a separate PowerShell window:" -ForegroundColor Yellow
    Write-Host "powershell.exe -EncodedCommand $encodedCommand" -ForegroundColor White
}

function Test-AVBlock {
    param (
        [string]$TestFolder
    )
    
    Write-Host "`n[TEST 2] Antivirus Block Simulation (Rule 100202)" -ForegroundColor Cyan
    Write-Host "----------------------------------------------" -ForegroundColor Cyan
    
    # Create a log file simulating an AV blocked message
    $avBlockLog = @"
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

The command 'suspicious_file.exe' was blocked by your antivirus software.
"@
    
    $avBlockLogPath = "$TestFolder\av_block_test.log"
    $avBlockLog | Out-File -FilePath $avBlockLogPath
    
    Write-Host "Created AV block simulation log at: $avBlockLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100202" -ForegroundColor Yellow
}

function Test-RiskyCmdlets {
    param (
        [string]$TestFolder
    )
    
    Write-Host "`n[TEST 3] Risky CMDLet Detection (Rule 100203)" -ForegroundColor Cyan
    Write-Host "-------------------------------------------" -ForegroundColor Cyan
    
    # Create a log file simulating risky cmdlet usage
    $riskyCmdletLog = @"
PowerShell Transcript
Start time: 20250408182700
Username: TESTUSER
RunAs User: TESTUSER
Machine: TESTPC
Host Application: PowerShell
Process ID: 1234

CommandInvocation(Get-VolumeShadowCopy): "Get-VolumeShadowCopy"
CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest -Uri https://example.com/test.txt -OutFile C:\test.txt"
"@
    
    $riskyCmdletLogPath = "$TestFolder\risky_cmdlet_test.log"
    $riskyCmdletLog | Out-File -FilePath $riskyCmdletLogPath
    
    Write-Host "Created risky cmdlet simulation log at: $riskyCmdletLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100203" -ForegroundColor Yellow
}

function Test-MshtaDownload {
    param (
        [string]$TestFolder
    )
    
    Write-Host "`n[TEST 4] MSHTA Download Detection (Rule 100204)" -ForegroundColor Cyan
    Write-Host "---------------------------------------------" -ForegroundColor Cyan
    
    # Create a PowerShell script block that contains MSHTA patterns
    $mshtaScriptBlock = @"
function Test-MshtaDownload {
    # This is a simulation of MSHTA download patterns
    # No actual execution occurs
    
    `$mshtaCode = @'
    <script language="JScript">
    var shell = new ActiveXObject("WScript.Shell");
    var url = "https://example.com/test.txt";
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    xhr.open("GET", url, false);
    xhr.send();
    shell.Run("cmd.exe /c echo " + xhr.responseText + " > c:\\test.txt");
    window.close();
    </script>
'@
    
    # Simulation of MSHTA command
    Write-Host "mshta.exe javascript:document.write('<script language=`"JScript`">var shell = new ActiveXObject(`"WScript.Shell`");shell.Run(`"calc.exe`");</script>')"
}

# Call the function
Test-MshtaDownload
"@
    
    $mshtaScriptPath = "$TestFolder\mshta_test.ps1"
    $mshtaScriptBlock | Out-File -FilePath $mshtaScriptPath
    
    Write-Host "Created MSHTA download simulation at: $mshtaScriptPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100204" -ForegroundColor Yellow
    Write-Host "NOTE: For accurate testing, run this script directly to generate a ScriptBlock log" -ForegroundColor Yellow
}

function Test-ExecutionPolicyBypass {
    param (
        [string]$TestFolder
    )
    
    Write-Host "`n[TEST 5] Execution Policy Bypass Detection (Rule 100205)" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------" -ForegroundColor Cyan
    
    # Create a log simulating execution policy bypass
    $bypassLog = @"
PowerShell Transcript
Start time: 20250408182700
Username: TESTUSER
RunAs User: TESTUSER
Machine: TESTPC
Host Application: PowerShell

ContextInfo: Host Name=ConsoleHost ExecutionPolicy=Bypass
ContextInfo: ExecutionPolicy bypass called by user script

CommandInvocation(Write-Host): "Write-Host 'Execution policy has been bypassed for this script'"
"@
    
    $bypassLogPath = "$TestFolder\policy_bypass_test.log"
    $bypassLog | Out-File -FilePath $bypassLogPath
    
    Write-Host "Created execution policy bypass simulation at: $bypassLogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100205" -ForegroundColor Yellow
    Write-Host "NOTE: For accurate testing, use the following command in a separate PowerShell window:" -ForegroundColor Yellow
    Write-Host "powershell.exe -ExecutionPolicy Bypass -Command 'Write-Host Test'" -ForegroundColor White
}

function Test-InvokeWebRequest {
    param (
        [string]$TestFolder
    )
    
    Write-Host "`n[TEST 6] Invoke-WebRequest Detection (Rule 100206)" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------" -ForegroundColor Cyan
    
    # Create a log simulating Invoke-WebRequest usage
    $iwr_log = @"
PowerShell Transcript
Start time: 20250408182700
Username: TESTUSER
RunAs User: TESTUSER
Machine: TESTPC
Host Application: PowerShell

ContextInfo: Invoke-WebRequest -Uri https://example.com/test.txt -OutFile C:\test.txt
ContextInfo: IWR -url https://example.com/test2.txt -OutFile C:\test2.txt

CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest -Uri https://example.com/test.txt -OutFile C:\test.txt"
"@
    
    $iwr_LogPath = "$TestFolder\invoke_webrequest_test.log"
    $iwr_log | Out-File -FilePath $iwr_LogPath
    
    Write-Host "Created Invoke-WebRequest simulation at: $iwr_LogPath" -ForegroundColor Green
    Write-Host "Expected to trigger Rule ID: 100206" -ForegroundColor Yellow
}

function Test-ALL {
    $testFolder = Initialize-TestEnvironment
    
    Write-Host "`nWhich test would you like to run?" -ForegroundColor Cyan
    Write-Host "1. Encoded Command Detection (Rule 100201)" -ForegroundColor White
    Write-Host "2. Antivirus Block Detection (Rule 100202)" -ForegroundColor White
    Write-Host "3. Risky CMDLet Detection (Rule 100203)" -ForegroundColor White
    Write-Host "4. MSHTA Download Detection (Rule 100204)" -ForegroundColor White
    Write-Host "5. Execution Policy Bypass Detection (Rule 100205)" -ForegroundColor White
    Write-Host "6. Invoke-WebRequest Detection (Rule 100206)" -ForegroundColor White
    Write-Host "7. All Tests" -ForegroundColor White
    Write-Host "Enter your choice (1-7): " -ForegroundColor Cyan -NoNewline
    
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Test-EncodedCommand -TestFolder $testFolder }
        "2" { Test-AVBlock -TestFolder $testFolder }
        "3" { Test-RiskyCmdlets -TestFolder $testFolder }
        "4" { Test-MshtaDownload -TestFolder $testFolder }
        "5" { Test-ExecutionPolicyBypass -TestFolder $testFolder }
        "6" { Test-InvokeWebRequest -TestFolder $testFolder }
        "7" {
            Test-EncodedCommand -TestFolder $testFolder
            Test-AVBlock -TestFolder $testFolder
            Test-RiskyCmdlets -TestFolder $testFolder
            Test-MshtaDownload -TestFolder $testFolder
            Test-ExecutionPolicyBypass -TestFolder $testFolder
            Test-InvokeWebRequest -TestFolder $testFolder
        }
        default {
            Write-Host "Invalid choice. Running all tests." -ForegroundColor Red
            Test-EncodedCommand -TestFolder $testFolder
            Test-AVBlock -TestFolder $testFolder
            Test-RiskyCmdlets -TestFolder $testFolder
            Test-MshtaDownload -TestFolder $testFolder
            Test-ExecutionPolicyBypass -TestFolder $testFolder
            Test-InvokeWebRequest -TestFolder $testFolder
        }
    }
    
    Write-Host "`n===================================================" -ForegroundColor Magenta
    Write-Host "PowerShell DETECTION TESTING COMPLETE" -ForegroundColor Magenta
    Write-Host "===================================================" -ForegroundColor Magenta
    Write-Host "Check your Wazuh dashboard for alerts." -ForegroundColor Yellow
    Write-Host "Filter by rule.id (100201-100206)" -ForegroundColor Yellow
    Write-Host "`nFor more accurate testing:" -ForegroundColor Yellow
    Write-Host "1. Ensure PowerShell Script Block Logging is enabled" -ForegroundColor White
    Write-Host "2. Run the suggested commands in a separate PowerShell window" -ForegroundColor White
    Write-Host "3. Check Wazuh alerts for rule matches" -ForegroundColor White
    Write-Host "===================================================" -ForegroundColor Magenta
    
    # Optional: clean up
    Write-Host "`nTest files created in: $testFolder" -ForegroundColor Cyan
    Write-Host "Would you like to remove the test files? (Y/N): " -ForegroundColor Cyan -NoNewline
    $cleanup = Read-Host
    
    if ($cleanup -eq "Y" -or $cleanup -eq "y") {
        Remove-Item -Path $testFolder -Recurse -Force
        Write-Host "Test files removed." -ForegroundColor Green
    }
    else {
        Write-Host "Test files kept for inspection at: $testFolder" -ForegroundColor Yellow
    }
}

# Run all tests
Test-ALL