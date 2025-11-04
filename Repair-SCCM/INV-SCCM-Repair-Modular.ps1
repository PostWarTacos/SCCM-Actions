<#
#   Intent: Modular invoke-command script using Base64 encoded resource scripts for SCCM repair operations
#   Author: Matthew Wurtz
#   Date: 04-Nov-25
#   Description: Uses Base64 encoded resource scripts to perform remote SCCM client removal, reboot, and reinstall operations
#>

# -------------------- FUNCTIONS -------------------- #

Function Get-FileName() {
    [CmdletBinding()]
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

function ConvertTo-Base64EncodedScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath
    )
    
    if (-not (Test-Path $ScriptPath)) {
        throw "Script file not found: $ScriptPath"
    }
    
    $scriptContent = Get-Content $ScriptPath -Raw -Encoding UTF8
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
    $encodedScript = [Convert]::ToBase64String($bytes)
    
    return $encodedScript
}

function Invoke-RemoteScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$EncodedScript,
        
        [Parameter()]
        [string]$ScriptDescription = "Remote Script"
    )
    
    Write-Host "Executing $ScriptDescription on $ComputerName..." -ForegroundColor Yellow
    
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($encodedScript)
            
            # Decode and execute the script
            $bytes = [Convert]::FromBase64String($encodedScript)
            $scriptContent = [System.Text.Encoding]::Unicode.GetString($bytes)
            
            # Execute the script in a new scope
            & ([ScriptBlock]::Create($scriptContent))
            
        } -ArgumentList $EncodedScript -ErrorAction Stop
        
        return $result
    } catch {
        Write-Error "Failed to execute $ScriptDescription on $ComputerName`: $_"
        return $false
    }
}

# -------------------- VARIABLES -------------------- #

# URLs on local machine
$desktop = [Environment]::GetFolderPath('Desktop')
$remediationSuccess = Join-Path $desktop "success.txt"
$remediationFail = Join-Path $desktop "fail.txt"

# Get targets
$targetFile = Get-FileName -initialDirectory $desktop
$targets = Get-Content $targetFile

# URLs for copying exe to machine
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
if ( $domain -match "DDS" ) {
    $cpSource = "\\scanz223\SMS_DDS\Client" # DDS
}
elseif ( $domain -match "DPOS" ) {
    $cpSource = "\\slrcp223\SMS_PCI\Client" # PCI
}

# File Check variables
$targetPath = "C:\drivers\ccm\ccmsetup"
$exeOnSrvr = Join-Path $cpSource "ccmsetup.exe"
[version]$correctVersion = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($exeOnSrvr)).FileVersion

# -------------------- LOAD AND ENCODE RESOURCE SCRIPTS -------------------- #

Write-Host "Loading and encoding resource scripts..." -ForegroundColor Cyan

# Build paths to resource scripts
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

# Encode scripts for remote execution
try {
    $encodedHealthCheck = ConvertTo-Base64EncodedScript -ScriptPath $healthCheckScript
    $encodedRemove = ConvertTo-Base64EncodedScript -ScriptPath $removeScript
    $encodedReinstall = ConvertTo-Base64EncodedScript -ScriptPath $reinstallScript
    Write-Host "✓ Resource scripts loaded and encoded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to encode resource scripts: $_"
    exit 1
}

# -------------------- FILE CHECK SCRIPT -------------------- #

$fileCheckScript = {
    param($targetPath_pass, [version]$correctVersion_pass)
    $valid = $false

    function Move-CCM {
        [cmdletbinding()]
        param(
            [parameter(Mandatory)]
            [string]$Source,
            [parameter(Mandatory)]
            [string]$Destination
        )

        $proc = Get-Process | Where-Object { $_.modules.filename -like "$source*" } -ErrorAction SilentlyContinue
        if ($proc) { Stop-Process $proc.Id -Force -ErrorAction SilentlyContinue }
        Move-Item -Path $Source -Destination $Destination -Force
    }

    $locations = @(
        @{ Path = "C:\drivers\ccm\ccmsetup"; Action = { 
            Write-Host "Correct location and version. Doing nothing."
            Remove-Item -Path "C:\drivers\ccmsetup" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\drivers\ccm\client" -Recurse -Force -ErrorAction SilentlyContinue
        }},
        @{ Path = "C:\drivers\ccm\client"; Action = {
            Write-Host "Renaming client to ccmsetup..."
            Rename-Item -Path "C:\drivers\ccm\client" -NewName "ccmsetup" -Force
            Remove-Item -Path "C:\drivers\ccmsetup" -Recurse -Force -ErrorAction SilentlyContinue
        }},
        @{ Path = "C:\drivers\ccmsetup"; Action = {
            Write-Host "Moving contents to $targetPath_pass..."
            if ( -not ( Test-Path $targetPath_pass )) { New-Item -ItemType Directory -Path $targetPath_pass | Out-Null }
            Move-CCM -Source "C:\drivers\ccmsetup" -Destination $targetPath_pass
            Remove-Item -Path "C:\drivers\ccmsetup" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\drivers\ccm\client" -Recurse -Force -ErrorAction SilentlyContinue
        }}
    )

    foreach ( $entry in $locations ) {
        $exePath = Join-Path $entry.Path "ccmsetup.exe"
        if ( Test-Path $exePath ) {
            $ver = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)).FileVersion
            if ( $ver -eq $correctVersion_pass ) {
                & $entry.Action
                $valid = $true
                break
            } else {
                Write-Warning "$exePath found, but version $ver is invalid. Removing..."
                Remove-Item -Path $exePath -Force
            }
        }
    }

    if ( -not $valid ) {
        return "Not Found"
    }
    return "Found"
}

# ------------------------------------------------------------
# Start of Target Machine Loop
# ------------------------------------------------------------

foreach ( $t in $targets ){

    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "Starting SCCM remediation on $t" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Cyan
    
    # Test connectivity
    Write-Host "Testing network connection to $t"
    $failedToConnect = if ( -not ( Test-Connection $t -Count 2 -Quiet )){
        Write-Host "Unable to connect to $t. Skipping it." -ForegroundColor Red
        Write-Output $t
        continue
    }

    # Reset variables to ensure correct results
    $removalResult = $null
    $installResult = $null

    # ------------------------------------------------------------
    # STEP 1: Initial Health Check
    # ------------------------------------------------------------
    
    Write-Host "`n--- Step 1: Initial Health Check ---" -ForegroundColor Cyan
    $initialHealthResult = Invoke-RemoteScript -ComputerName $t -EncodedScript $encodedHealthCheck -ScriptDescription "Health Check"
    if ($initialHealthResult) {
        Write-Host "Initial health status: $initialHealthResult" -ForegroundColor Yellow
    }

    # ------------------------------------------------------------
    # STEP 2: Execute Remove-SCCM Script
    # ------------------------------------------------------------

    Write-Host "`n--- Step 2: SCCM Removal ---" -ForegroundColor Cyan
    $removalResult = Invoke-RemoteScript -ComputerName $t -EncodedScript $encodedRemove -ScriptDescription "SCCM Removal"
    
    if ($removalResult -eq $false) {
        Write-Host "✗ SCCM removal failed on $t" -ForegroundColor Red
        "$t failed during removal" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    } else {
        Write-Host "✓ SCCM removal completed on $t" -ForegroundColor Green
    }

    # ------------------------------------------------------------
    # STEP 3: File Check and Copy if needed
    # ------------------------------------------------------------
    
    Write-Host "`n--- Step 3: File Verification ---" -ForegroundColor Cyan
    
    try {
        $fileCheck = Invoke-Command -ComputerName $t -ScriptBlock $fileCheckScript -ArgumentList $targetPath, $correctVersion
        
        if ( $fileCheck -eq "Not Found" ){
            Write-Host "Copying SCCM installation files to $t..." -ForegroundColor Yellow
            $cpDestination = "\\$t\C$\drivers\ccm\ccmsetup"
            robocopy $cpSource $cpDestination /E /Z /MT:4 /R:1 /W:2 /NP /V | Out-Null
            Write-Host "✓ File copy completed for $t" -ForegroundColor Green
        } else {
            Write-Host "✓ Valid SCCM installer found on $t" -ForegroundColor Green
        }
    } catch {
        Write-Warning "File check/copy failed on $t`: $_"
    }

    # ------------------------------------------------------------
    # STEP 4: Reboot and Wait
    # ------------------------------------------------------------

    Write-Host "`n--- Step 4: Reboot ---" -ForegroundColor Cyan

    try {
        $initialBootTime = Invoke-Command -ComputerName $t { 
            (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        }
        
        Write-Host "Initiating reboot of $t..." -ForegroundColor Yellow
        Restart-Computer -ComputerName $t -Force
        
        # Wait for reboot to complete
        Write-Host "Waiting for $t to reboot..." -ForegroundColor Yellow
        do {
            Start-Sleep -Seconds 60
            try {
                $currentBootTime = (Get-CimInstance -ComputerName $t -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
            } catch {
                $currentBootTime = $initialBootTime
            }
        } while ( $currentBootTime -le $initialBootTime )

        # Additional wait for services to start
        Write-Host "Waiting for services to start..." -ForegroundColor Yellow
        Start-Sleep -Seconds 120
        Write-Host "✓ $t has rebooted successfully" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to reboot $t`: $_" -ForegroundColor Red
        "$t failed to reboot" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 5: Execute Reinstall-SCCM Script
    # ------------------------------------------------------------

    Write-Host "`n--- Step 5: SCCM Reinstallation ---" -ForegroundColor Cyan
    $installResult = Invoke-RemoteScript -ComputerName $t -EncodedScript $encodedReinstall -ScriptDescription "SCCM Reinstallation"
    
    if ($installResult -eq $false -or $installResult -eq 201) {
        Write-Host "✗ SCCM reinstallation failed on $t" -ForegroundColor Red
        "$t failed during installation" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
    } else {
        Write-Host "✓ SCCM reinstallation completed successfully on $t" -ForegroundColor Green
    }

    # ------------------------------------------------------------
    # STEP 6: Final Health Check
    # ------------------------------------------------------------
    
    Write-Host "`n--- Step 6: Final Health Check ---" -ForegroundColor Cyan
    $finalHealthResult = Invoke-RemoteScript -ComputerName $t -EncodedScript $encodedHealthCheck -ScriptDescription "Final Health Check"
    if ($finalHealthResult) {
        Write-Host "Final health status: $finalHealthResult" -ForegroundColor Yellow
    }

    # ------------------------------------------------------------
    # STEP 7: Record Results
    # ------------------------------------------------------------

    Write-Host "`n--- Results Summary ---" -ForegroundColor Cyan

    # Determine overall success
    if ($removalResult -and $installResult -and $installResult -ne $false -and $installResult -ne 201) {
        $t | Out-File -Append -FilePath $remediationSuccess -Encoding UTF8
        Write-Host "✓ $t - Overall remediation SUCCESSFUL" -ForegroundColor Green
    } else {
        if ($removalResult -eq $false) {
            "$t failed to uninstall" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        } elseif ($installResult -eq $false -or $installResult -eq 201) {
            "$t failed to install" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        }
        Write-Host "✗ $t - Overall remediation FAILED" -ForegroundColor Red
    }

    # Handle failed connections
    if ( $failedToConnect ){
        foreach ( $f in $failedToConnect ){
            "$f failed to connect" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        }
    }
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