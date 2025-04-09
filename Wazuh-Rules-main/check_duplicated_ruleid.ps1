# Wazuh Rule ID Duplicate Checker
# Script to find duplicate rule IDs in Wazuh XML rule files

# Set the path to the Wazuh-Rules directory
$rulesDir = "C:\temp\Wazuh-Rules-main"

# Function to extract rule IDs from XML files
function Extract-RuleIds {
    param (
        [string]$filePath
    )

    $ruleIds = @()
    
    try {
        $content = Get-Content -Path $filePath -Raw
        
        # Use regex to find all rule IDs
        $regex = [regex]'<rule\s+id="(\d+)"'
        $matches = $regex.Matches($content)
        
        foreach ($match in $matches) {
            $ruleIds += $match.Groups[1].Value
        }
    }
    catch {
        Write-Warning "Could not process file: $filePath"
        Write-Warning "Error: $_"
    }
    
    return $ruleIds
}

# Main script
Write-Host "Checking for duplicate rule IDs in $rulesDir" -ForegroundColor Cyan

# Get all XML files in the directory (recursively)
$xmlFiles = Get-ChildItem -Path $rulesDir -Filter "*.xml" -Recurse

Write-Host "Found $($xmlFiles.Count) XML files to check" -ForegroundColor Green

# Dictionary to store rule IDs and their file paths
$ruleIdMap = @{}
$duplicateRuleIds = @{}

# Process each XML file
foreach ($file in $xmlFiles) {
    $filePath = $file.FullName
    $relPath = $filePath.Substring($rulesDir.Length + 1)
    
    Write-Host "Processing $relPath..." -ForegroundColor Gray
    
    $ruleIds = Extract-RuleIds -filePath $filePath
    
    foreach ($ruleId in $ruleIds) {
        if ($ruleIdMap.ContainsKey($ruleId)) {
            # Found a duplicate
            if (-not $duplicateRuleIds.ContainsKey($ruleId)) {
                $duplicateRuleIds[$ruleId] = @($ruleIdMap[$ruleId])
            }
            $duplicateRuleIds[$ruleId] += $relPath
        }
        else {
            # First occurrence
            $ruleIdMap[$ruleId] = $relPath
        }
    }
}

# Report results
Write-Host "`nAnalysis Complete" -ForegroundColor Cyan
Write-Host "Total unique rule IDs found: $($ruleIdMap.Count)" -ForegroundColor Green

# Fixed the if/else statement by placing them properly with proper syntax
if ($duplicateRuleIds.Count -eq 0) {
    Write-Host "No duplicate rule IDs found!" -ForegroundColor Green
} else {
    Write-Host "Found $($duplicateRuleIds.Count) duplicate rule IDs:" -ForegroundColor Red
    
    foreach ($ruleId in $duplicateRuleIds.Keys | Sort-Object) {
        Write-Host "`nRule ID $ruleId appears in:" -ForegroundColor Yellow
        foreach ($file in $duplicateRuleIds[$ruleId]) {
            Write-Host " - $file" -ForegroundColor White
        }
    }
}

Write-Host "`nPress Enter to exit..."
$null = Read-Host