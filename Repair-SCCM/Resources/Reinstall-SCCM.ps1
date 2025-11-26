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
Write-LogMessage -message "(Step 1 of 5) Verifying and repairing WMI and Windows Installer services."

# Always reset WMI repository before SCCM installation to prevent MOF compilation errors
# WMI can appear healthy but still have corruption that breaks MOF compilation
Write-LogMessage -message "Resetting WMI repository to ensure clean state for SCCM installation..."
try {
    # Stop WMI service
    Write-LogMessage -message "Stopping WMI service..."
    Stop-Service -Name Winmgmt -Force -ErrorAction Stop
    Start-Sleep -Seconds 3
    
    # Reset WMI repository
    Write-LogMessage -message "Resetting WMI repository..."
    $wmiadapPath = Join-Path $env:SystemRoot "System32\wbem\winmgmt.exe"
    $resetProc = Start-Process -FilePath $wmiadapPath -ArgumentList "/resetrepository" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    
    if ($resetProc.ExitCode -eq 0) {
        Write-LogMessage -Level Success -Message "WMI repository reset successfully."
    } else {
        Write-LogMessage -Level Warning -Message "WMI reset returned exit code: $($resetProc.ExitCode)"
    }
    
    Start-Sleep -Seconds 3
    
    # Start WMI service
    Write-LogMessage -message "Starting WMI service..."
    Start-Service -Name Winmgmt -ErrorAction Stop
    Start-Sleep -Seconds 5
    
    # Verify WMI is responsive
    $wmiTest = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($wmiTest) {
        Write-LogMessage -Level Success -Message "WMI service is running and responsive after reset."
    } else {
        Write-LogMessage -Level Warning -Message "WMI service started but query test failed."
    }
}
catch {
    Write-LogMessage -Level Error -Message "Failed to reset WMI: $_"
    Write-LogMessage -Level Warning -Message "Continuing with installation attempt anyway..."
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

Write-LogMessage -message "(Step 2 of 5) Attempting reinstall."
try {
    # Configure installation parameters based on site code
    # DDS site installation with simplified parameters
    if ( $SiteCode -eq "DDS") {
        # Note: Commented line shows full parameter set for future reference
        $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$SiteCode" -PassThru -Verbose
    }
    # PCI site installation with site code specification
    elseif ( $SiteCode -eq "PCI" ) {
        $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$SiteCode" -PassThru -Verbose    
    }
       
    # Wait for installation process to complete and vlidate exit code
    $proc.WaitForExit()
    if ( $proc.ExitCode -ne 0 ){
        throw "SCCM install failed with exit code $($proc.exitcode)"
    }
    Write-LogMessage -Level Success -Message "Reinstall complete."
    
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

