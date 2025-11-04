<#
#   Intent: Modular invoke-command script that imports and executes SCCM repair scripts against target machines
#   Author: Matthew Wurtz
#   Date: 04-Nov-25
#   Description: Uses resource scripts from Resources folder to perform SCCM client removal, reboot, and reinstall operations
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

Function Import-ResourceScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ScriptName
    )
    
    $resourcesPath = Join-Path $PSScriptRoot "Resources"
    $scriptPath = Join-Path $resourcesPath "$ScriptName.ps1"
    
    if (-not (Test-Path $scriptPath)) {
        throw "Resource script not found: $scriptPath"
    }
    
    # Read and return the script content for invoke-command execution
    $scriptContent = Get-Content $scriptPath -Raw -Encoding UTF8
    return $scriptContent
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

# Import resource scripts
Write-Host "Loading resource scripts..." -ForegroundColor Cyan
try {
    $removeScript = Import-ResourceScript -ScriptName "Remove-SCCM"
    $reinstallScript = Import-ResourceScript -ScriptName "Reinstall-SCCM"
    $healthCheckScript = Import-ResourceScript -ScriptName "Check-SCCMHealth"
    Write-Host "✓ Resource scripts loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load resource scripts: $_"
    exit 1
}

# ------------------------------------------------------------
# Start of Target Machine Loop
# ------------------------------------------------------------

foreach ( $t in $targets ){

    Write-Host "Starting SCCM remediation on $t" -ForegroundColor Green
    
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
    # STEP 1: Health Check (Optional - to see current state)
    # ------------------------------------------------------------
    
    Write-Host "Checking current SCCM health status on $t..." -ForegroundColor Yellow
    try {
        $healthResult = Invoke-Command -ComputerName $t -ScriptBlock ([ScriptBlock]::Create($healthCheckScript)) -ErrorAction Stop
        Write-Host "Health check result: $healthResult" -ForegroundColor Cyan
    } catch {
        Write-Warning "Health check failed on $t`: $_"
    }

    # ------------------------------------------------------------
    # STEP 2: Execute Remove-SCCM Script
    # ------------------------------------------------------------

    Write-Host "Executing SCCM removal on $t..." -ForegroundColor Yellow
    
    # Create a script block that adapts the Remove-SCCM script for invoke-command
    $removeScriptBlock = [ScriptBlock]::Create(@"
# Modify the Remove-SCCM script to work with invoke-command
# Remove interactive prompts and adapt for remote execution
$removeScriptModified = @'
$($removeScript -replace 'Get-UserInputWithTimeout[^}]+}', '' -replace 'Read-Host[^"]*"[^"]*"', '"y"' -replace 'exit 1', 'return $false' -replace 'Restart-Computer -Force', 'return "REBOOT_REQUIRED"')
'@

# Execute the modified script
Invoke-Expression $removeScriptModified
"@)

    try {
        $removalResult = Invoke-Command -ComputerName $t -ScriptBlock $removeScriptBlock -ErrorAction Stop
        
        if ($removalResult -eq $false) {
            Write-Host "✗ SCCM removal failed on $t" -ForegroundColor Red
            "$t failed during removal" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
            continue
        } elseif ($removalResult -eq "REBOOT_REQUIRED") {
            Write-Host "✓ SCCM removal completed on $t - reboot required" -ForegroundColor Green
        } else {
            Write-Host "✓ SCCM removal completed on $t" -ForegroundColor Green
        }
    } catch {
        Write-Host "✗ Failed to execute removal script on $t`: $_" -ForegroundColor Red
        "$t failed to connect for removal" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 3: File Check and Copy if needed
    # ------------------------------------------------------------
    
    Write-Host "Verifying SCCM installer files on $t..." -ForegroundColor Yellow
    
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

    Write-Host "Rebooting $t and waiting for it to come back online..." -ForegroundColor Yellow

    try {
        $initialBootTime = Invoke-Command -ComputerName $t { 
            (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        }
        
        Restart-Computer -ComputerName $t -Force -Wait
        
        # Wait for reboot to complete
        do {
            Start-Sleep -Seconds 60
            try {
                $currentBootTime = (Get-CimInstance -ComputerName $t -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
            } catch {
                $currentBootTime = $initialBootTime
            }
        } while ( $currentBootTime -le $initialBootTime )

        # Additional wait for services to start
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

    Write-Host "Executing SCCM reinstallation on $t..." -ForegroundColor Yellow
    
    # Create a script block that adapts the Reinstall-SCCM script for invoke-command
    $reinstallScriptBlock = [ScriptBlock]::Create(@"
# Modify the Reinstall-SCCM script to work with invoke-command
# Remove interactive prompts and adapt for remote execution
$reinstallScriptModified = @'
$($reinstallScript -replace 'Get-UserInputWithTimeout[^}]+}', '' -replace 'Read-Host[^"]*"[^"]*"', '"DDS"' -replace 'exit 1', 'return $false')
'@

# Execute the modified script
Invoke-Expression $reinstallScriptModified
"@)

    try {
        $installResult = Invoke-Command -ComputerName $t -ScriptBlock $reinstallScriptBlock -ErrorAction Stop
        
        if ($installResult -eq $false -or $installResult -eq 201) {
            Write-Host "✗ SCCM reinstallation failed on $t" -ForegroundColor Red
            "$t failed during installation" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        } else {
            Write-Host "✓ SCCM reinstallation completed successfully on $t" -ForegroundColor Green
        }
    } catch {
        Write-Host "✗ Failed to execute reinstall script on $t`: $_" -ForegroundColor Red
        "$t failed to connect for reinstall" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        $installResult = $false
    }

    # ------------------------------------------------------------
    # STEP 6: Final Health Check
    # ------------------------------------------------------------
    
    Write-Host "Performing final health check on $t..." -ForegroundColor Yellow
    try {
        $finalHealthResult = Invoke-Command -ComputerName $t -ScriptBlock ([ScriptBlock]::Create($healthCheckScript)) -ErrorAction Stop
        Write-Host "Final health check result: $finalHealthResult" -ForegroundColor Cyan
    } catch {
        Write-Warning "Final health check failed on $t`: $_"
    }

    # ------------------------------------------------------------
    # STEP 7: Record Results
    # ------------------------------------------------------------

    Write-Host "Completed work on $t" -ForegroundColor Green

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

    Write-Host "----------------------------------------" -ForegroundColor Gray
}

# ----------------------------------------
# End of Target Machine Loop
# ----------------------------------------

Write-Host "Completed all target machines!!" -ForegroundColor Green
Write-Host "Check results in:" -ForegroundColor Cyan
Write-Host "  Success: $remediationSuccess" -ForegroundColor Green
Write-Host "  Failures: $remediationFail" -ForegroundColor Red