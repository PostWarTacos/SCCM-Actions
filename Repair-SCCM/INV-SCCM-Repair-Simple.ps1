<#
#   Intent: Simple invoke-command script that uses existing resource scripts via -FilePath
#   Author: Matthew Wurtz
#   Date: 04-Nov-25
#   Description: Loops through target PCs and uses Invoke-Command -FilePath to execute resource scripts directly
#>

# -------------------- FUNCTIONS -------------------- #

Function Get-FileName() {
    param (
        [Parameter(Mandatory)]
        [string]$initialDirectory
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.initialDirectory = $initialDirectory
    $openFileDialog.filter = "All files (*.*)| *.*"
    $openFileDialog.ShowDialog() | Out-Null
    $openFileDialog.filename
}

# -------------------- VARIABLES -------------------- #

# Get target file
$desktop = [Environment]::GetFolderPath('Desktop')
$remediationSuccess = Join-Path $desktop "success.txt"
$remediationFail = Join-Path $desktop "fail.txt"

Write-Host "Select target file containing list of computers..." -ForegroundColor Cyan
$targetFile = Get-FileName -initialDirectory $desktop
$targets = Get-Content $targetFile

# Build paths to existing resource scripts
$resourcesPath = Join-Path $PSScriptRoot "Resources"
$healthCheckScript = Join-Path $resourcesPath "Check-SCCMHealth.ps1"
$removeScript = Join-Path $resourcesPath "Remove-SCCM.ps1"
$reinstallScript = Join-Path $resourcesPath "Reinstall-SCCM.ps1"

# Validate script paths exist
$scriptPaths = @{
    'healthCheckScript' = $healthCheckScript
    'removeScript' = $removeScript
    'reinstallScript' = $reinstallScript
}

foreach ($name in $scriptPaths.Keys) {
    if (-not (Test-Path $scriptPaths[$name])) {
        Write-Error "Required script file not found: $($scriptPaths[$name])"
        exit 1
    }
}

# Determine SCCM source path using robust domain detection
Write-Host "✓ Found all required resource scripts" -ForegroundColor Green

# ------------------------------------------------------------
# Start of Target Machine Loop
# ------------------------------------------------------------

foreach ( $t in $targets ){

    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "Starting SCCM remediation on $t" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Cyan
    
    # Test connectivity
    Write-Host "Testing network connection to $t"
    if ( -not ( Test-Connection $t -Count 2 -Quiet )){
        Write-Host "Unable to connect to $t. Skipping it." -ForegroundColor Red
        "$t failed to connect" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # Reset variables to ensure correct results
    $healthResult = $null
    $removalResult = $null
    $installResult = $null

    # ------------------------------------------------------------
    # STEP 1: Initial Health Check
    # ------------------------------------------------------------
    
    Write-Host "`n--- Step 1: Initial Health Check ---" -ForegroundColor Cyan
    try {
        $healthResult = Invoke-Command -ComputerName $t -FilePath $healthCheckScript -ErrorAction Stop
        Write-Host "Initial health status: $healthResult" -ForegroundColor Yellow
    } catch {
        Write-Warning "Initial health check failed on $t`: $_"
    }

    # ------------------------------------------------------------
    # STEP 2: Execute Remove-SCCM Script
    # ------------------------------------------------------------

    Write-Host "`n--- Step 2: SCCM Removal ---" -ForegroundColor Cyan
    try {
        $removalResult = Invoke-Command -ComputerName $t -FilePath $removeScript -ErrorAction Stop
        Write-Host "✓ SCCM removal script executed on $t" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to execute removal script on $t`: $_" -ForegroundColor Red
        "$t failed during removal" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 3: Execute Reinstall-SCCM Script  
    # ------------------------------------------------------------

    Write-Host "`n--- Step 3: SCCM Reinstallation ---" -ForegroundColor Cyan
    try {
        $installResult = Invoke-Command -ComputerName $t -FilePath $reinstallScript -ErrorAction Stop
        Write-Host "✓ SCCM reinstall script executed on $t" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to execute reinstall script on $t`: $_" -ForegroundColor Red
        "$t failed during installation" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 4: Final Health Check
    # ------------------------------------------------------------
    
    Write-Host "`n--- Step 4: Final Health Check ---" -ForegroundColor Cyan
    try {
        $finalHealthResult = Invoke-Command -ComputerName $t -FilePath $healthCheckScript -ErrorAction Stop
        Write-Host "Final health status: $finalHealthResult" -ForegroundColor Yellow
    } catch {
        Write-Warning "Final health check failed on $t`: $_"
    }

    # ------------------------------------------------------------
    # STEP 5: Record Results
    # ------------------------------------------------------------

    Write-Host "`n--- Results Summary ---" -ForegroundColor Cyan

    # Record success - let the resource scripts determine actual success/failure
    $t | Out-File -Append -FilePath $remediationSuccess -Encoding UTF8
    Write-Host "✓ $t - Scripts executed successfully" -ForegroundColor Green
}

# ----------------------------------------
# End of Target Machine Loop
# ----------------------------------------

Write-Host "`n============================================" -ForegroundColor Green
Write-Host "Completed all target machines!!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "Check results in:" -ForegroundColor Cyan
Write-Host "  ✓ Successes: $remediationSuccess" -ForegroundColor Green
Write-Host "  ✗ Failures:  $remediationFail" -ForegroundColor Red