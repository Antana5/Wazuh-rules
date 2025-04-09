# LSASS Dump Testing Script
# This script demonstrates and tests various LSASS dumping techniques
# FOR TESTING AND EDUCATIONAL PURPOSES ONLY
# Must be run with Administrator privileges

# Create output directory for test dumps
$TestDir = "$env:USERPROFILE\AppData\Local\Temp\LsassDumpTests"
New-Item -Path $TestDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Created test directory: $TestDir" -ForegroundColor Cyan

# Function to create dummy test files to simulate LSASS dumps (no actual dumping)
function Create-DummyDumpFile {
    param(
        [string]$FileName,
        [string]$Technique
    )
    
    $FilePath = Join-Path -Path $TestDir -ChildPath $FileName
    "This is a dummy file simulating an LSASS dump using $Technique. Created $(Get-Date)" | Out-File -FilePath $FilePath
    Write-Host "Created dummy file for technique '$Technique': $FilePath" -ForegroundColor Green
}

# Function to clean up
function Cleanup {
    Write-Host "`nCleaning up..." -ForegroundColor Yellow
    Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed test directory: $TestDir" -ForegroundColor Yellow
}

# Register cleanup on script exit
trap {
    Cleanup
    break
}

try {
    # 1. Task Manager Technique - Simulated
    Write-Host "`n=== Task Manager Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-taskmanager.DMP" -Technique "Task Manager"
    
    # 2. ProcDump Technique - Simulated
    Write-Host "`n=== ProcDump Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-procdump.dmp" -Technique "ProcDump"
    
    # 3. PowerShell Out-MiniDump - Simulated
    Write-Host "`n=== PowerShell Out-MiniDump Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-minidump.dmp" -Technique "PowerShell Out-MiniDump"
    
    # 4. Comsvcs.dll Technique - Simulated
    Write-Host "`n=== Comsvcs.dll Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-comsvcs.dmp" -Technique "Comsvcs.dll MiniDump"
    
    # 5. WerFault Technique - Simulated
    Write-Host "`n=== WerFault Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-werfault.dmp" -Technique "WerFault"
    
    # 6. Direct MiniDumpWriteDump API - Simulated
    Write-Host "`n=== Direct MiniDumpWriteDump API Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-api.dmp" -Technique "MiniDumpWriteDump API"
    
    # 7. Silent Process Exit Technique - Simulated
    Write-Host "`n=== Silent Process Exit Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-silent-exit.dmp" -Technique "Silent Process Exit"
    
    # 8. Process Snapshot Technique - Simulated
    Write-Host "`n=== Process Snapshot Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-snapshot.dmp" -Technique "Process Snapshot"

    # 9. Volume Shadow Copy Technique - Simulated
    Write-Host "`n=== Volume Shadow Copy Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "lsass-shadow.dmp" -Technique "Volume Shadow Copy"
    
    # 10. Custom minidump - Simulated
    Write-Host "`n=== Custom Minidump Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "custom-no-lsass-name.dmp" -Technique "Custom Minidump without LSASS in name"

    # 11. Obfuscated name dumping - Simulated
    Write-Host "`n=== Obfuscated Name Technique (Simulated) ===" -ForegroundColor Cyan
    Create-DummyDumpFile -FileName "totally-not-lsass.bin" -Technique "Obfuscated name dumping"
    Create-DummyDumpFile -FileName "svchost-legit.dmp" -Technique "Misleading name dumping"
    
    # Additional evasion techniques - uncommon locations
    Write-Host "`n=== Uncommon Locations (Simulated) ===" -ForegroundColor Cyan
    $UncommonDirs = @(
        (Join-Path -Path $env:TEMP -ChildPath "SubDir1\SubDir2"),
        (Join-Path -Path $env:PUBLIC -ChildPath "Documents\Resources"),
        (Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Templates")
    )
    
    foreach ($Dir in $UncommonDirs) {
        New-Item -Path $Dir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        $FileName = "data_$(Get-Random).dmp"
        $FilePath = Join-Path -Path $Dir -ChildPath $FileName
        "This is a dummy file simulating an LSASS dump in uncommon location. Created $(Get-Date)" | Out-File -FilePath $FilePath
        Write-Host "Created dummy file in uncommon location: $FilePath" -ForegroundColor Green
    }

    # List all created files for verification
    Write-Host "`n=== All Created Test Files ===" -ForegroundColor Magenta
    Get-ChildItem -Path $TestDir -Recurse | Select-Object FullName | Format-Table -AutoSize
    
    # Additional locations
    Write-Host "`n=== Files in Uncommon Locations ===" -ForegroundColor Magenta
    foreach ($Dir in $UncommonDirs) {
        Get-ChildItem -Path $Dir -ErrorAction SilentlyContinue | Select-Object FullName | Format-Table -AutoSize
    }
    
    # Wait for events to be processed
    Write-Host "`nWaiting for events to be processed by Sysmon..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    
    # Prompt before cleanup
    $response = Read-Host -Prompt "`nDo you want to clean up all test files? (Y/N)"
    if ($response.ToUpper() -eq "Y") {
        Cleanup
        # Clean up additional locations
        foreach ($Dir in $UncommonDirs) {
            Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Removed uncommon location dir: $Dir" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Skipping cleanup. Remember to manually remove test files when done." -ForegroundColor Yellow
    }
    
    Write-Host "`nScript completed successfully. Check your Wazuh alerts for detected events." -ForegroundColor Green
}
catch {
    Write-Host "Error encountered: $_" -ForegroundColor Red
    Cleanup
}