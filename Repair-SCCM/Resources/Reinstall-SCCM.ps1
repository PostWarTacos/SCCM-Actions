<#
.SYNOPSIS
    Reinstalls SCCM (System Center Configuration Manager) client and performs health verification.

.DESCRIPTION
    This script performs a complete reinstallation of the SCCM client for specified site codes.
    It handles the installation process, waits for services to initialize, runs health checks,
    and verifies the client is functioning properly through comprehensive validation tests.

    The script supports two key output modes:
    - When run in a non-interactive PowerShell session (scheduled tasks, automation, or via Invoke-SCCMRepair.ps1), it uses exit codes (0 for success, 1 for failure).
    - When run in an interactive PowerShell session (such as via Collection Commander or a user shell), it returns string results for status.

.PARAMETER SiteCode
    The SCCM site code for the installation. Valid values are:
    - DDS: Data Distribution Service site
    - PCI: Primary Care Interface site

.PARAMETER Invoke
    Switch to indicate the script is being run interactively (e.g., via Collection Commander).
    When specified, the script will output status messages to the console with color coding.

.EXAMPLE
    .\Reinstall-SCCM.ps1 -SiteCode "DDS"
    Reinstalls SCCM client for the DDS site code.

.EXAMPLE
    .\Reinstall-SCCM.ps1 -SiteCode "PCI"
    Reinstalls SCCM client for the PCI site code.

.NOTES
    File Name      : Reinstall-SCCM.ps1
    Version        : 1.3
    Last Updated   : 2025-11-20
    Author         : System Administrator
    Prerequisite   : Administrator privileges required
                   : SCCM setup files must be present in C:\drivers\ccm\ccmsetup\

.OUTPUTS
    - Interactive PowerShell session: Returns string status for Collection Commander and similar tools.
    - Non-interactive session (scheduled/automated): Returns exit code (0 for success, 1 for failure) for automation and Invoke-SCCMRepair.ps1.
    - All actions are logged to both console (if enabled) and log file.

.LINK
    Related scripts: Check-SCCMHealth.ps1, Remove-SCCM.ps1
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("DDS", "PCI")]
    [string]$SiteCode,
    [bool]$Invoke = $false
)

# -------------------- FUNCTIONS -------------------- #

Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory)]
        [string]$Message,
        [Parameter(Position=1)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Default")]
        [string]$Level,
        [string]$LogFile = "$healthLogPath\HealthCheck.txt"
    )
    
    # Generate timestamp for log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes for visual identification    
    if ($Level) {
        $prefix = switch ($Level) {
            "Info"    { "[*]" }     # Informational messages
            "Warning" { "[!]" }     # Warning messages  
            "Error"   { "[!!!]" }   # Error messages
            "Success" { "[+]" }     # Success messages
        }
    }
    else {
        $prefix = "[*]" # Default prefix for unspecified level
        $Level = "Default"
    }

    
    $logEntry = "[$timestamp] $prefix $Message"

    # Display console output with appropriate colors for each level (only when $Invoke switch is used)
    if ($script:Invoke) {
        switch ($Level) {
            "Default" { Write-Host $logEntry -ForegroundColor DarkGray }
            "Info"    { Write-Host $logEntry -ForegroundColor White }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            "Error"   { Write-Host $logEntry -ForegroundColor Red }
            "Success" { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    
    # Write to log file if specified
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -ErrorAction Stop
        } catch {
            # Use Write-Warning to avoid recursion when logging fails
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Test-HealthCheck {
    
    # Initialize success flag - will be set to false if any check fails
    $allPassed = $true

    # Verify SCCM Client executable exists in expected location
    if ( Test-Path "C:\Windows\CCM\CcmExec.exe" ) {
        Write-LogMessage -Level Success -Message "Found CcmExec.exe. SCCM installed."
    } else {
        Write-LogMessage -Level Error -Message "Cannot find CcmExec.exe."
        $allPassed = $false
    }

    # Verify SCCM Client Service exists and is in running state
    $service = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    if ( $service.Status -eq 'Running' ) {
        Write-LogMessage -Level Success -Message "Found CcmExec service and it is running."
    } elseif ( $service.Status -ne 'Running' ) {
        Write-LogMessage -Level Error -Message "Found CcmExec service but it is NOT running."
        $allPassed = $false
    } else {
        Write-LogMessage -Level Error -Message "CcmExec service could not be found."
        $allPassed = $false
    }

    # Retrieve and validate SCCM client version from WMI namespace
    $smsClient = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue
    if ( $smsClient.ClientVersion ) {
        Write-LogMessage -Level Success -Message "SCCM Client Version: $($smsClient.ClientVersion)"
    } else {
        Write-LogMessage -Level Error -Message "Client Version not found."
        $allPassed = $false
    }

    # Validate SCCM site assignment through SMS_Authority WMI class
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction SilentlyContinue
    if ( $mp.Name ) {
        Write-LogMessage -Level Success -Message "SCCM Site found: $($mp.Name)"
    } else {
        Write-LogMessage -Level Error -Message "SMS_Authority.Name property not found."
        $allPassed = $false
    }

    # Verify unique client identifier is properly assigned
    $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction SilentlyContinue
    if ($ccmClient.ClientId) {
        Write-LogMessage -Level Success -Message "SCCM Client Client ID found: $($ccmClient.ClientId)"
    } else {
        Write-LogMessage -Level Error -Message "Client Id property not found."
        $allPassed = $false
    }

    # Confirm management point FQDN is accessible and configured
    if ($mp.CurrentManagementPoint) {
        Write-LogMessage -Level Success -Message "SCCM Management Point found: $($mp.CurrentManagementPoint)"
    } else {
        Write-LogMessage -Level Error -Message "Management Point property not found."
        $allPassed = $false
    }

    return $allPassed
}

# -------------------- VARIABLES -------------------- #

# Health check retry configuration
$maxAttempts = 3        # Maximum number of health check attempts before giving up
$success = $false       # Flag to track overall success status

# Standard directory paths for SCCM operations
$healthLogPath = "C:\drivers\ccm\logs"        # Location for health check log files
$localInstallerPath = "C:\drivers\ccm\ccmsetup" # Location of SCCM installation files

# Site code configuration (passed as mandatory parameter from calling script)
# Valid values: DDS (Data Distribution Service) or PCI (Primary Care Interface)

# -------------------- REINSTALL SCCM -------------------- #

Write-LogMessage -message "Starting SCCM reinstallation for site code: $SiteCode"
Write-LogMessage -message "Session Mode: $(if ($Invoke) { 'Interactive' } else { 'Non-Interactive (Scheduled Task/Service)' })"

# -------------------- FIX WMI AND WINDOWS INSTALLER -------------------- #
Write-LogMessage -message "(Step 1 of 5) Preparing system for SCCM installation."

# CRITICAL: Remove any Windows Installer registration of SCCM to force clean install
Write-LogMessage -message "Removing SCCM product registrations from Windows Installer database..."

# Known SCCM product GUID from logs
$sccmProductGuid = "{987AABAD-F544-404E-86C6-215EAFBEB7C0}"

try {
    # Target the specific product GUID first
    $guidPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$sccmProductGuid",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$sccmProductGuid"
    )
    
    foreach ($path in $guidPaths) {
        if (Test-Path $path) {
            Write-LogMessage -Level Warning -Message "Found SCCM product registration: $path"
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-LogMessage -Level Success -Message "Removed product registration"
            }
            catch {
                Write-LogMessage -Level Error -Message "Failed to remove $path : $_"
            }
        }
    }
    
    # Also sweep for any Configuration Manager entries
    $productKeys = @()
    $productKeys += Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Where-Object {
        $displayName = $_.GetValue("DisplayName")
        $displayName -like "*Configuration Manager*" -or $displayName -like "*System Center*"
    }
    $productKeys += Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Where-Object {
        $displayName = $_.GetValue("DisplayName")
        $displayName -like "*Configuration Manager*" -or $displayName -like "*System Center*"
    }
    
    if ($productKeys.Count -gt 0) {
        Write-LogMessage -Level Warning -Message "Found $($productKeys.Count) additional SCCM-related registration(s)."
        foreach ($key in $productKeys) {
            $displayName = $key.GetValue("DisplayName")
            Write-LogMessage -Level Warning -Message "Removing: '$displayName' at $($key.PSPath)"
            try {
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                Write-LogMessage -Level Success -Message "Removed registry key"
            }
            catch {
                Write-LogMessage -Level Error -Message "Failed to remove: $_"
            }
        }
    }
    
    # Clean Windows Installer cached package database and component registrations
    Write-LogMessage -message "Cleaning Windows Installer database for SCCM components..."
    try {
        $removedCount = 0
        
        # Remove from UserData\Products (per-machine installations)
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products") {
            Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products" -ErrorAction SilentlyContinue | ForEach-Object {
                $productKey = $_
                $installProps = Get-ItemProperty -Path "$($productKey.PSPath)\InstallProperties" -ErrorAction SilentlyContinue
                if ($installProps.DisplayName -like "*Configuration Manager*" -or $installProps.DisplayName -like "*CCM*") {
                    try {
                        Write-LogMessage -Level Warning -Message "Removing installer product: $($installProps.DisplayName)"
                        Remove-Item -Path $productKey.PSPath -Recurse -Force -ErrorAction Stop
                        $removedCount++
                    }
                    catch {
                        Write-LogMessage -Level Warning -Message "Could not remove product: $_"
                    }
                }
            }
        }
        
        # Remove from UserData\Components (this is what causes baseline detection!)
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components") {
            $componentCount = 0
            Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components" -ErrorAction SilentlyContinue | ForEach-Object {
                $componentKey = $_
                $values = Get-ItemProperty -Path $componentKey.PSPath -ErrorAction SilentlyContinue
                # Check if any value points to CCM or SCCM paths
                $hasSCCM = $false
                foreach ($prop in $values.PSObject.Properties) {
                    if ($prop.Value -match "CCM|SMS|Configuration Manager") {
                        $hasSCCM = $true
                        break
                    }
                }
                
                if ($hasSCCM) {
                    try {
                        Remove-Item -Path $componentKey.PSPath -Recurse -Force -ErrorAction Stop
                        $componentCount++
                    }
                    catch {
                        # Component may be in use
                    }
                }
            }
            if ($componentCount -gt 0) {
                Write-LogMessage -Level Success -Message "Removed $componentCount SCCM component registrations"
                $removedCount += $componentCount
            }
        }
        
        # Remove from UpgradeCodes
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes") {
            Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes" -ErrorAction SilentlyContinue | ForEach-Object {
                $upgradeKey = $_
                $values = Get-ItemProperty -Path $upgradeKey.PSPath -ErrorAction SilentlyContinue
                foreach ($prop in $values.PSObject.Properties) {
                    if ($prop.Name -eq $sccmProductGuid.ToUpper().Replace("{","").Replace("}","").Replace("-","")) {
                        try {
                            Remove-ItemProperty -Path $upgradeKey.PSPath -Name $prop.Name -Force -ErrorAction Stop
                            Write-LogMessage -Level Success -Message "Removed upgrade code reference"
                            $removedCount++
                        }
                        catch {}
                    }
                }
            }
        }
        
        # Clean Windows Installer Folders cache (physical MSI files)
        Write-LogMessage -message "Cleaning Windows Installer Folders cache..."
        $installerFolders = "$env:SystemRoot\Installer"
        if (Test-Path $installerFolders) {
            # Find all MSI files that contain SCCM/CCM in their summary info
            Get-ChildItem "$installerFolders\*.msi" -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $msiPath = $_.FullName
                    # Use Windows Installer COM object to read MSI properties
                    $installer = New-Object -ComObject WindowsInstaller.Installer
                    $database = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($msiPath, 0))
                    $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @("SELECT Value FROM Property WHERE Property='ProductName'"))
                    $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)
                    $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
                    
                    if ($record) {
                        $productName = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
                        if ($productName -like "*Configuration Manager*" -or $productName -like "*System Center*") {
                            Write-LogMessage -Level Warning -Message "Found cached MSI: $productName at $msiPath"
                            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($record) | Out-Null
                            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($view) | Out-Null
                            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($database) | Out-Null
                            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($installer) | Out-Null
                            
                            # Remove the cached MSI file
                            Remove-Item -Path $msiPath -Force -ErrorAction Stop
                            Write-LogMessage -Level Success -Message "Removed cached MSI file"
                            $removedCount++
                        }
                    }
                }
                catch {
                    # COM errors or file in use - skip
                }
            }
        }
        
        # Clean InProgressInstallInfo (this tracks active/incomplete installations)
        Write-LogMessage -message "Cleaning incomplete installation tracking..."
        $inProgressPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgressInstallInfo"
        if (Test-Path $inProgressPath) {
            Get-ChildItem $inProgressPath -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.ProductName -like "*Configuration Manager*" -or $props.ProductName -like "*System Center*") {
                    Write-LogMessage -Level Warning -Message "Removing incomplete install tracking: $($props.ProductName)"
                    Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
                    $removedCount++
                }
            }
        }
        
        # Clean PendingFileRenameOperations (Windows Installer pending operations)
        Write-LogMessage -message "Clearing pending file operations..."
        $pendingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $pendingOps = Get-ItemProperty -Path $pendingPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingOps) {
            $opsArray = $pendingOps.PendingFileRenameOperations
            $filteredOps = @()
            $removed = 0
            
            for ($i = 0; $i -lt $opsArray.Count; $i++) {
                if ($opsArray[$i] -notmatch "CCM|SMS|Configuration Manager") {
                    $filteredOps += $opsArray[$i]
                }
                else {
                    $removed++
                }
            }
            
            if ($removed -gt 0) {
                if ($filteredOps.Count -eq 0) {
                    Remove-ItemProperty -Path $pendingPath -Name "PendingFileRenameOperations" -Force -ErrorAction Stop
                    Write-LogMessage -Level Success -Message "Removed all SCCM pending file operations"
                }
                else {
                    Set-ItemProperty -Path $pendingPath -Name "PendingFileRenameOperations" -Value $filteredOps -Force -ErrorAction Stop
                    Write-LogMessage -Level Success -Message "Removed $removed SCCM pending file operations"
                }
                $removedCount += $removed
            }
        }
        
        # Clean Patches registry (MSP patch cache that references the product)
        Write-LogMessage -message "Cleaning MSI patch cache..."
        $patchesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Patches"
        if (Test-Path $patchesPath) {
            Get-ChildItem $patchesPath -ErrorAction SilentlyContinue | ForEach-Object {
                $patchKey = $_
                $props = Get-ItemProperty -Path $patchKey.PSPath -ErrorAction SilentlyContinue
                # Check if patch references SCCM product GUID
                $transformedGuid = $sccmProductGuid.ToUpper().Replace("{","").Replace("}","").Replace("-","")
                if ($props.PSObject.Properties.Name -contains $transformedGuid) {
                    Write-LogMessage -Level Warning -Message "Removing patch registration for SCCM"
                    Remove-Item -Path $patchKey.PSPath -Recurse -Force -ErrorAction Stop
                    $removedCount++
                }
            }
        }
        
        if ($removedCount -eq 0) {
            Write-LogMessage -Level Info -Message "No SCCM entries found in Windows Installer database"
        } else {
            Write-LogMessage -Level Success -Message "Removed $removedCount Windows Installer entries"
        }
    }
    catch {
        Write-LogMessage -Level Warning -Message "Error cleaning installer database: $_"
    }
    
    # Force Windows Installer to rebuild cache by stopping/starting service
    Write-LogMessage -message "Restarting Windows Installer service to clear cache..."
    try {
        Restart-Service -Name msiserver -Force -ErrorAction Stop
        Start-Sleep -Seconds 3
        Write-LogMessage -Level Success -Message "Windows Installer service restarted"
    }
    catch {
        Write-LogMessage -Level Warning -Message "Could not restart Windows Installer service: $_"
    }
    
    # Verify the product GUID is no longer registered
    $stillExists = $false
    foreach ($path in $guidPaths) {
        if (Test-Path $path) {
            Write-LogMessage -Level Error -Message "CRITICAL: Product GUID still exists at $path after removal attempt!"
            $stillExists = $true
        }
    }
    
    if (-not $stillExists) {
        Write-LogMessage -Level Success -Message "Verified: SCCM product GUID removed from registry"
    }
}
catch {
    Write-LogMessage -Level Error -Message "Error during product registration cleanup: $_"
}

# Ensure SCCM namespaces are completely removed
Write-LogMessage -message "Verifying SCCM namespaces are removed..."
try {
    $namespacesToCheck = @(
        @{Namespace="root"; Name="CCM"},
        @{Namespace="root"; Name="CCMVDI"},
        @{Namespace="root"; Name="SmsDm"},
        @{Namespace="root\cimv2"; Name="sms"}
    )
    
    $foundNamespaces = @()
    foreach ($ns in $namespacesToCheck) {
        $exists = Get-CimInstance -Query "Select * From __Namespace Where Name='$($ns.Name)'" -Namespace $ns.Namespace -ErrorAction SilentlyContinue
        if ($exists) {
            $foundNamespaces += "$($ns.Namespace)\$($ns.Name)"
            Write-LogMessage -Level Warning -Message "Found existing namespace: $($ns.Namespace)\$($ns.Name)"
            try {
                $exists | Remove-CimInstance -Confirm:$false -ErrorAction Stop
                Write-LogMessage -Level Success -Message "Removed $($ns.Namespace)\$($ns.Name)"
            }
            catch {
                Write-LogMessage -Level Error -Message "Failed to remove $($ns.Namespace)\$($ns.Name): $_"
            }
        }
    }
    
    if ($foundNamespaces.Count -eq 0) {
        Write-LogMessage -Level Success -Message "Verified: No SCCM namespaces present."
    } else {
        Write-LogMessage -Level Warning -Message "Removed $($foundNamespaces.Count) existing SCCM namespace(s)."
    }
}
catch {
    Write-LogMessage -Level Warning -Message "Error checking namespaces: $_"
}

    # Verify WMI is functional and repository is healthy
Write-LogMessage -message "Verifying WMI service status and repository health..."
try {
    $wmiService = Get-Service -Name Winmgmt -ErrorAction Stop
    if ($wmiService.Status -ne 'Running') {
        Write-LogMessage -Level Warning -Message "WMI service not running. Starting..."
        Start-Service -Name Winmgmt -ErrorAction Stop
        Start-Sleep -Seconds 10
    } else {
        Write-LogMessage -Level Success -Message "WMI service is running."
    }
    
    # Check WMI repository consistency before MOF testing
    Write-LogMessage -message "Checking WMI repository consistency..."
    try {
        $repoCheck = & winmgmt.exe /verifyrepository 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Level Success -Message "WMI repository is consistent"
        } else {
            Write-LogMessage -Level Warning -Message "WMI repository verification failed. Attempting salvage..."
            Stop-Service -Name Winmgmt -Force -ErrorAction Stop
            Start-Sleep -Seconds 5
            $null = & winmgmt.exe /salvagerepository 2>&1
            Start-Sleep -Seconds 10
            Start-Service -Name Winmgmt -ErrorAction Stop
            Start-Sleep -Seconds 10
            
            # Verify again after salvage
            $repoCheck2 = & winmgmt.exe /verifyrepository 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-LogMessage -Level Error -Message "WMI repository still inconsistent after salvage. Performing FULL RESET..."
                Write-LogMessage -Level Warning -Message "This will destroy all WMI data and rebuild from scratch. This is required for SCCM installation to succeed."
                
                Stop-Service -Name Winmgmt -Force -ErrorAction Stop
                Start-Sleep -Seconds 5
                
                # Nuclear option: complete repository reset
                $null = & winmgmt.exe /resetrepository 2>&1
                Start-Sleep -Seconds 30  # Reset takes much longer
                
                Start-Service -Name Winmgmt -ErrorAction Stop
                Start-Sleep -Seconds 15
                
                # Final verification
                $repoCheck3 = & winmgmt.exe /verifyrepository 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-LogMessage -Level Success -Message "WMI repository reset and verified"
                } else {
                    throw "WMI repository reset failed - manual intervention required"
                }
            } else {
                Write-LogMessage -Level Success -Message "WMI repository salvaged successfully"
            }
        }
    }
    catch {
        Write-LogMessage -Level Warning -Message "Could not verify WMI repository: $_"
    }    # CRITICAL FIX: Test WMI MOF compilation capability (not just query ability)
    # The error 80041002 happens during MOF compilation, so we need to test that specifically
    Write-LogMessage -message "Testing WMI MOF compilation capability..."
    $mofTestPassed = $false
    try {
        # First verify basic WMI connectivity
        $null = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        
        # Now test MOF compilation by creating a simple test MOF file
        $testMofPath = "$env:TEMP\WMITest_$(Get-Date -Format 'yyyyMMddHHmmss').mof"
        $testMofContent = @"
#pragma namespace("\\\\.\\root\\cimv2")

[dynamic, provider("CIMWin32")]
class WMI_Test_Class
{
    [key] string TestKey;
    string TestValue;
};
"@
        Set-Content -Path $testMofPath -Value $testMofContent -Force
        
        # Try to compile the test MOF using mofcomp.exe
        $mofcompPath = Join-Path $env:SystemRoot "System32\wbem\mofcomp.exe"
        $mofcompResult = & $mofcompPath $testMofPath 2>&1
        $mofcompExitCode = $LASTEXITCODE
        
        # Clean up test MOF file
        Remove-Item -Path $testMofPath -Force -ErrorAction SilentlyContinue
        
        if ($mofcompExitCode -eq 0) {
            Write-LogMessage -Level Success -Message "WMI MOF compilation test passed."
            
            # Clean up the test class we created
            try {
                $testClass = Get-CimClass -ClassName "WMI_Test_Class" -Namespace "root\cimv2" -ErrorAction SilentlyContinue
                if ($testClass) {
                    Remove-CimClass -InputObject $testClass -ErrorAction SilentlyContinue
                }
            }
            catch {}
            
            $mofTestPassed = $true
        }
        else {
            throw "MOF compilation failed with exit code $mofcompExitCode. Output: $mofcompResult"
        }
    }
    catch {
        Write-LogMessage -Level Warning -Message "WMI MOF compilation test failed: $_"
        Write-LogMessage -Level Warning -Message "Attempting WMI repository repair..."
        
        try {
            # Stop WMI service
            Stop-Service -Name Winmgmt -Force -ErrorAction Stop
            Start-Sleep -Seconds 5
            
            # Try salvage first (preserves data)
            Write-LogMessage -message "Attempting repository salvage..."
            $salvageResult = & winmgmt.exe /salvagerepository 2>&1
            Start-Sleep -Seconds 5
            
            # Restart WMI
            Start-Service -Name Winmgmt -ErrorAction Stop
            Start-Sleep -Seconds 10
            
            # Re-test MOF compilation after salvage
            $testMofPath = "$env:TEMP\WMITest_$(Get-Date -Format 'yyyyMMddHHmmss').mof"
            Set-Content -Path $testMofPath -Value $testMofContent -Force
            $mofcompPath = Join-Path $env:SystemRoot "System32\wbem\mofcomp.exe"
            $mofcompResult = & $mofcompPath $testMofPath 2>&1
            $mofcompExitCode = $LASTEXITCODE
            Remove-Item -Path $testMofPath -Force -ErrorAction SilentlyContinue
            
            if ($mofcompExitCode -eq 0) {
                Write-LogMessage -Level Success -Message "WMI repository salvaged successfully - MOF compilation now works"
                $mofTestPassed = $true
            }
            else {
                throw "MOF compilation still fails after salvage"
            }
        }
        catch {
            Write-LogMessage -Level Error -Message "WMI salvage failed: $_"
            Write-LogMessage -Level Warning -Message "Attempting aggressive repository reset..."
            
            try {
                # Last resort: full repository reset (loses all WMI data)
                Stop-Service -Name Winmgmt -Force -ErrorAction Stop
                Start-Sleep -Seconds 5
                
                Write-LogMessage -message "Performing WMI repository reset (this may take several minutes)..."
                $resetResult = & winmgmt.exe /resetrepository 2>&1
                Start-Sleep -Seconds 30  # Reset takes much longer than salvage
                
                Start-Service -Name Winmgmt -ErrorAction Stop
                Start-Sleep -Seconds 15
                
                # Final test
                $null = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                Write-LogMessage -Level Success -Message "WMI repository reset completed"
                $mofTestPassed = $true
            }
            catch {
                Write-LogMessage -Level Error -Message "WMI repository reset failed: $_"
                Write-LogMessage -Level Error -Message "CRITICAL: WMI is corrupted and cannot be repaired automatically"
                Write-LogMessage -Level Warning -Message "Installation will likely fail. Manual WMI repair may be required."
            }
        }
    }
}
catch {
    Write-LogMessage -Level Error -Message "WMI test failed: $_"
    Write-LogMessage -Level Warning -Message "Installation may fail due to WMI issues."
}

# Test Windows Installer service
Write-LogMessage -message "Verifying Windows Installer service..."
$msiNeedsRepair = $false
try {
    $msiService = Get-Service -Name msiserver -ErrorAction Stop
    
    if ($msiService.Status -in @('Running', 'Stopped') -and $msiService.StartType -ne 'Disabled') {
        $msiexecPath = Join-Path $env:SystemRoot "System32\msiexec.exe"
        if (Test-Path $msiexecPath) {
            Write-LogMessage -Level Success -Message "Windows Installer service is accessible and healthy."
        } else {
            Write-LogMessage -Level Warning -Message "msiexec.exe not found. Will attempt repair."
            $msiNeedsRepair = $true
        }
    } else {
        Write-LogMessage -Level Warning -Message "Windows Installer service is in an unhealthy state. Will attempt repair."
        $msiNeedsRepair = $true
    }
}
catch {
    Write-LogMessage -Level Warning -Message "Windows Installer test encountered error: $_. Will attempt repair."
    $msiNeedsRepair = $true
}

# Repair Windows Installer if needed
if ($msiNeedsRepair) {
    Write-LogMessage -message "Repairing Windows Installer service..."
    try {
        Stop-Service -Name msiserver -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/unregister" -Wait -PassThru -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 2
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/regserver" -Wait -PassThru -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 2
        
        Start-Service -Name msiserver -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        $msiService = Get-Service -Name msiserver
        if ($msiService.Status -eq 'Running') {
            Write-LogMessage -Level Success -Message "Windows Installer service repaired successfully."
        } else {
            throw "Windows Installer service failed to start after re-registration."
        }
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to repair Windows Installer: $_"
        Write-LogMessage -Level Warning -Message "Continuing with installation attempt anyway..."
    }
}

if (-not $script:Invoke) {
    Write-Output "Step 1 - WMI and Windows Installer repair completed."
}

# CRITICAL: Restart WMI service immediately before installation to ensure clean state
# This prevents MOF file locks and namespace conflicts during installation
Write-LogMessage -message "Restarting WMI service to ensure clean state for installation..."
try {
    # First, remove any corrupted MDM WMI classes that cause 80041002 errors
    Write-LogMessage -message "Checking for corrupted MDM_ConfigSetting WMI class..."
    try {
        $mdmClass = Get-CimClass -ClassName "MDM_ConfigSetting" -Namespace "root\cimv2\mdm\dmmap" -ErrorAction SilentlyContinue
        if ($mdmClass) {
            Write-LogMessage -Level Warning -Message "Found MDM_ConfigSetting class - removing to prevent WMI conflicts..."
            Get-CimInstance -ClassName "MDM_ConfigSetting" -Namespace "root\cimv2\mdm\dmmap" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
            Write-LogMessage -Level Success -Message "Removed MDM_ConfigSetting instances"
        }
    }
    catch {
        # MDM namespace may not exist or be accessible - this is fine
        Write-LogMessage -Level Info -Message "MDM namespace not accessible (expected on non-MDM systems)"
    }
    
    Restart-Service -Name Winmgmt -Force -ErrorAction Stop
    Start-Sleep -Seconds 10
    Write-LogMessage -Level Success -Message "WMI service restarted successfully"
}
catch {
    Write-LogMessage -Level Warning -Message "Could not restart WMI service: $_"
}

# Force uninstall via msiexec if product GUID still registered
Write-LogMessage -message "Forcing uninstall of any remaining SCCM product via msiexec..."
try {
    $sccmProductGuid = "{987AABAD-F544-404E-86C6-215EAFBEB7C0}"
    
    # Try silent uninstall with no UI
    Write-LogMessage -message "Running: msiexec.exe /x $sccmProductGuid /qn /norestart"
    $uninstallProc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $sccmProductGuid /qn /norestart" -Wait -PassThru -NoNewWindow
    
    if ($uninstallProc.ExitCode -eq 0) {
        Write-LogMessage -Level Success -Message "msiexec uninstall completed successfully (exit code 0)"
    }
    elseif ($uninstallProc.ExitCode -eq 1605) {
        Write-LogMessage -Level Success -Message "Product not installed (exit code 1605) - good for clean install"
    }
    else {
        Write-LogMessage -Level Warning -Message "msiexec uninstall returned exit code $($uninstallProc.ExitCode)"
    }
    
    Start-Sleep -Seconds 3
}
catch {
    Write-LogMessage -Level Warning -Message "msiexec uninstall encountered error: $_"
}

Write-LogMessage -message "(Step 2 of 5) Attempting reinstall."
try {
    # Configure installation parameters
    # Using /logon to run in foreground/blocking mode for reliable exit code detection
    # Aggressive cache cleanup above should prevent cached baseline detection issues
    # CRITICAL: Must specify /mp: because AD query returns 0 MPs (error 0x87d00215)
    # Multiple MPs specified - SCCM will auto-select the best one based on network proximity
    $setupProcess = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$SiteCode /mp:VCANZ221.dds.dillards.net;VOTCZ222.dds.dillards.net;VOTCZ223.dds.dillards.net" -PassThru -Verbose
    $setupProcess.WaitForExit()
    $exitCode = $setupProcess.ExitCode
    Write-LogMessage -message "ccmsetup.exe completed with exit code: $exitCode"
    
    # Check for installation failure
    # Exit code 0 = Success, 7 = Reboot required (also success), any other = failure
    if ($exitCode -eq 0 -or $exitCode -eq 7) {
        if ($exitCode -eq 7) {
            Write-LogMessage -Level Warning -Message "ccmsetup.exe completed successfully but requires reboot (exit code 7)"
        }
        Write-LogMessage -Level Success -Message "Reinstall process initiated."
    }
    else {
        Write-LogMessage -Level Error -Message "ccmsetup.exe failed with exit code $exitCode"
        if (-not $script:Invoke) {        # Query all Management Points for DDS site
        Get-WmiObject -Namespace "root\sms\site_DDS" -Class SMS_SCI_SysResUse -ComputerName "SCANZ223" | 
            Where-Object {$_.RoleName -eq "SMS Management Point"} | 
            Select-Object NetworkOSPath, NALPath, RoleName
            Write-Output "Step 2 - SCCM reinstall failed with exit code $exitCode"
        }
        throw "SCCM installation failed with exit code $exitCode"
    }
    # Monitor service installation - ccmexec service creation can take time
    Write-LogMessage -message "Waiting for service to be installed."
    if ($Host.Name -eq 'ConsoleHost') { return "ReinstallComplete" }
    $ccmexecWaitCount = 0
    $maxServiceWaitAttempts = 15  # Wait up to 30 minutes (15 * 120 seconds)
    while ( -not ( Get-Service "ccmexec" -ErrorAction SilentlyContinue ) -and $ccmexecWaitCount -lt $maxServiceWaitAttempts) {
        $ccmexecWaitCount++
        Write-LogMessage -message "Service not yet installed. Waiting... (Attempt $ccmexecWaitCount of $maxServiceWaitAttempts)"
        Start-Sleep -Seconds 120  # Check every 2 minutes
    }
    
    if (-not (Get-Service "ccmexec" -ErrorAction SilentlyContinue)) {
        throw "SCCM service was not installed after waiting $($maxServiceWaitAttempts * 2) minutes."
    }
    
    # Wait for service to reach running state before proceeding
    Write-LogMessage -message "Waiting for service to show running."
    $ccmexecRunWaitCount = 0
    $maxRunWaitAttempts = 15  # Wait up to 30 minutes
    while ( (Get-Service "ccmexec" -ErrorAction SilentlyContinue).Status -ne "Running" -and $ccmexecRunWaitCount -lt $maxRunWaitAttempts) {
        $ccmexecRunWaitCount++
        $currentStatus = (Get-Service "ccmexec" -ErrorAction SilentlyContinue).Status
        Write-LogMessage -message "Service status: $currentStatus. Waiting for Running state... (Attempt $ccmexecRunWaitCount of $maxRunWaitAttempts)"
        Start-Sleep -Seconds 120  # Check every 2 minutes
    }
    
    $finalStatus = (Get-Service "ccmexec" -ErrorAction SilentlyContinue).Status
    if ($finalStatus -ne "Running") {
        Write-LogMessage -Level Warning -Message "Service is in state: $finalStatus (not Running). Continuing anyway..."
    } else {
        Write-LogMessage -Level Success -Message "SCCM service is running."
    }
    if (-not $script:Invoke){
        Write-Output "Step 2 - SCCM reinstall succeeded. Proceeding with health checks."  # Output for Collection Commander
    }
}
Catch{
    Write-LogMessage -Level Error -Message "Install failed. Caught error: $_"
    if (-not $script:Invoke){
        Write-Output "Step 2 - SCCM reinstall failed. Return $_"  # Output for Collection Commander
    }
    return $_
}

# -------------------- REGISTER AND RUN CCMEVAL CHECK -------------------- #

    # Execute SCCM's built-in evaluation tool to perform initial client validation
Write-LogMessage -message "(Step 3 of 5) Registering CcmEval. Running CcmEval check."
C:\windows\ccm\CcmEval.exe /register  # Register CcmEval scheduled task
C:\windows\ccm\CcmEval.exe /run       # Execute immediate evaluation

# After running CcmEval, check ccmeval.log for registration failure and cross-validate
$ccmevalLog = "C:\Windows\CCM\Logs\ccmeval.log"
if (Test-Path $ccmevalLog) {
    $ccmevalTail = Get-Content $ccmevalLog -Tail 40
    $regFailLine = $ccmevalTail | Select-String -Pattern "Client registered check: FAILED"
    if ($regFailLine) {
        Write-LogMessage -Level Error -Message "CcmEval reported registration failure. Validating against previous health checks..."
        if ($Host.Name -eq 'ConsoleHost') { return "CcmEvalFailed" }
        if ($clientIdFound) {
            Write-LogMessage -Level Info -Message "ClientId was found in health check, so registration may have succeeded after initial failure."
        } else {
            Write-LogMessage -Level Warning -Message "ClientId not found in health check. Pulling diagnostic logs for further analysis."
            $cidLog = "C:\Windows\CCM\Logs\ClientIDManagerStartup.log"
            $locLog = "C:\Windows\CCM\Logs\LocationServices.log"
            if (Test-Path $cidLog) {
                Write-LogMessage -Level Info -Message "Last 20 lines of ClientIDManagerStartup.log:"
                Get-Content $cidLog -Tail 20 | ForEach-Object { Write-LogMessage -Level Info -Message $_ }
            } else {
                Write-LogMessage -Level Warning -Message "ClientIDManagerStartup.log not found."
            }
            if (Test-Path $locLog) {
                Write-LogMessage -Level Info -Message "Last 20 lines of LocationServices.log:"
                Get-Content $locLog -Tail 20 | ForEach-Object { Write-LogMessage -Level Info -Message $_ }
            } else {
                Write-LogMessage -Level Warning -Message "LocationServices.log not found."
            }
        }
    }
    if (-not $script:Invoke){
        Write-Output "Step 3 - CcmEval check completed."  # Output for Collection Commander
    }
}

# -------------------- RUN UNTIL ALL PASS OR TIMEOUT -------------------- #
Write-LogMessage -message "(Step 4 of 5) Running custom health checks."
Write-LogMessage -message "Pausing for 180 seconds (3 minutes) before verifying client is operating correctly."
Start-Sleep -Seconds 180  # Allow time for client initialization after CcmEval

# Retry loop for health validation with configurable attempts
for ( $i = 1; $i -le $maxAttempts; $i++ ) {
    Write-LogMessage -message "---- Health Check Attempt $i ----"

    # Execute comprehensive health validation
    if ( Test-HealthCheck ) {
        Write-LogMessage -Level Success -Message "All SCCM health checks passed!"
        $success = $true
        break  # Exit loop on success
    }

    # Wait before next attempt (except on final attempt)
    if ( $i -lt $maxAttempts ) {
        Start-Sleep -Seconds 120  # 2-minute delay between attempts
    }
}

# Final validation and return appropriate exit code
if (-not $Invoke) {
    # Collection Commander: Only return one status at end
    if (-not $success) {
        Write-LogMessage -Level Error -Message "Health checks did not pass after $maxAttempts attempts."
        return "Health Check Failed"
    } else {
        Write-LogMessage -Level Success -Message "All SCCM health checks passed!"
        return "Reinstall Success"
    }
} else {
    # Non-Collection Commander: preserve previous logic (multiple returns)
    if (-not $success) {
        Write-LogMessage -Level Error -Message "Health checks did not pass after $maxAttempts attempts."
        return 1 # Indicate failure with exit code 1
    } else {
        Write-LogMessage -Level Success -Message "All SCCM health checks passed!"
        return 0 # Implicit success return (exit code 0) if all health checks passed
    }
}

