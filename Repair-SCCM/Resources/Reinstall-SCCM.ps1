<#
.SYNOPSIS
    Reinstalls SCCM (System Center Configuration Manager) client and performs health verification.

.DESCRIPTION
    This script performs a complete reinstallation of the SCCM client for specified site codes.
    It handles the installation process, waits for services to initialize, runs health checks,
    and verifies the client is functioning properly through comprehensive validation tests.

.PARAMETER SiteCode
    The SCCM site code for the installation. Valid values are:
    - DDS: Data Distribution Service site
    - PCI: Primary Care Interface site

.EXAMPLE
    .\Reinstall-SCCM.ps1 -SiteCode "DDS"
    Reinstalls SCCM client for the DDS site code.

.EXAMPLE
    .\Reinstall-SCCM.ps1 -SiteCode "PCI"
    Reinstalls SCCM client for the PCI site code.

.NOTES
    File Name      : Reinstall-SCCM.ps1
    Version        : 1.3
    Last Updated   : 2025-11-14
    Author         : System Administrator
    Prerequisite   : Administrator privileges required
                   : SCCM setup files must be present in C:\drivers\ccm\ccmsetup\
    
.OUTPUTS
    - Success: Returns 0 (implicit)
    - Failure: Returns 201 for health check failures, or error object for installation failures
    - Log files written to: C:\drivers\ccm\logs\HealthCheck.txt

.LINK
    Related scripts: Check-SCCMHealth.ps1, Remove-SCCM.ps1
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("DDS", "PCI")]
    [string]$SiteCode
)

# -------------------- FUNCTIONS -------------------- #

<#
.SYNOPSIS
    Determines if the PowerShell session is running interactively or non-interactively.
.DESCRIPTION
    Checks if the PowerShell session is running interactively (manual execution)
    or non-interactively (scheduled task, service, etc.). This affects how the
    script handles user prompts and output display.
    
    The function detects non-interactive sessions by:
    - Checking if parent process is svchost.exe (Task Scheduler service)
    - Verifying if no console session exists (SESSIONNAME environment variable)
    - Detecting if running in background/service context
.OUTPUTS
    Returns $true if session is interactive, $false if non-interactive
.EXAMPLE
    $isInteractive = Test-InteractiveSession
    if ($isInteractive) {
        # Show prompts and wait for user input
    } else {
        # Run silently without prompts
    }
#>
function Test-InteractiveSession {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        # Start with assumption that session is interactive
        $isInteractive = $true
        
        # Get current process information
        $currentProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue
        
        if ($currentProcess) {
            # Get parent process information
            $parentProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($currentProcess.ParentProcessId)" -ErrorAction SilentlyContinue
            
            # Check if parent process is svchost.exe (Task Scheduler service)
            # or if no console session exists (SESSIONNAME environment variable is null)
            if ($parentProcess -and ($parentProcess.Name -eq "svchost.exe" -or $env:SESSIONNAME -eq $null)) {
                $isInteractive = $false
            }
            
            # Additional checks for non-interactive contexts
            if ($isInteractive) {
                # Check if running in Windows Service context
                if ($env:USERNAME -eq "SYSTEM" -or $env:USERNAME -eq "LOCAL SERVICE" -or $env:USERNAME -eq "NETWORK SERVICE") {
                    $isInteractive = $false
                }
                
                # Check if console host is available
                try {
                    [System.Console]::KeyAvailable | Out-Null
                } catch {
                    # If console is not available, likely non-interactive
                    $isInteractive = $false
                }
            }
        }
        
        return $isInteractive
        
    } catch {
        # If detection fails, assume non-interactive to be safe
        # This prevents hanging on prompts in automated environments
        return $false
    }
}

<#
.SYNOPSIS
    Writes formatted log messages to console and file with timestamp and level indicators.

.DESCRIPTION
    This function provides consistent logging across the script with color-coded console output
    and file logging capabilities. Messages are timestamped and prefixed with level indicators.

.PARAMETER Level
    The severity level of the message (Info, Warning, Error, Success)

.PARAMETER Message
    The message content to log

.PARAMETER LogFile
    Optional path to log file. Defaults to the health log path.
#>
Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [string]$LogFile = "$healthLogPath\HealthCheck.txt"
    )
    
    # Generate timestamp for log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes for visual identification
    $prefix = switch ($Level) {
        "Info"    { "[*]" }      # Informational messages
        "Warning" { "[!]" }      # Warning messages  
        "Error"   { "[!!!]" }    # Error messages
        "Success" { "[+]" }      # Success messages
    }
    
    # Build the complete log entry with timestamp and prefix
    if (-not $prefix) {
        $logEntry = "[$timestamp] $Message"
    }
    else {
        $logEntry = "[$timestamp] $prefix $Message"
    }

    # Display console output with appropriate colors for each level (only when running interactively)
    if ($isInteractive) {
        switch ($Level) {
            "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            "Error"   { Write-Host $logEntry -ForegroundColor Red }
            "Success" { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    
    # Write to log file if specified
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        } catch {
            # Use Write-Warning to avoid recursion when logging fails
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
    
    # Add to health log array for backward compatibility with existing code
    $healthLog.Add($logEntry) | Out-Null
}

<#
.SYNOPSIS
    Performs comprehensive health checks on the SCCM client installation. Slimmed down version of Check-SCCMHealth.ps1.

.DESCRIPTION
    This function validates multiple aspects of SCCM client health including:
    - Client executable presence
    - Service status
    - Client version information
    - Management point connectivity
    - Client ID assignment

.OUTPUTS
    Returns $true if all health checks pass, $false otherwise
#>
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
    if ( $ccmClient.ClientId ) {
        Write-LogMessage -Level Success -Message "SCCM Client Client ID found: $($ccmClient.ClientId)"
    } else {
        Write-LogMessage -Level Error -Message "Client Id property not found."
        $allPassed = $false
    }

    # Confirm management point FQDN is accessible and configured
    if ( $mp.CurrentManagementPoint ) {
        Write-LogMessage -Level Success -Message "SCCM Management Point found: $($mp.CurrentManagementPoint)"
    } else {
        Write-LogMessage -Level Error -Message "Management Point property not found."
        $allPassed = $false
    }

    return $allPassed
}

# -------------------- VARIABLES -------------------- #

# Initialize mutable array list for collecting log entries throughout execution
$healthLog = [System.Collections.ArrayList]@()

# Health check retry configuration
$maxAttempts = 3        # Maximum number of health check attempts before giving up
$success = $false       # Flag to track overall success status

# Standard directory paths for SCCM operations
$healthLogPath = "C:\drivers\ccm\logs"        # Location for health check log files
$localInstallerPath = "C:\drivers\ccm\ccmsetup" # Location of SCCM installation files

# Site code configuration (passed as mandatory parameter from calling script)
# Valid values: DDS (Data Distribution Service) or PCI (Primary Care Interface)

# Session detection - determines if running interactively or as scheduled task
$isInteractive = Test-InteractiveSession

# -------------------- REINSTALL SCCM -------------------- #

Write-LogMessage -Level Info -Message "Starting SCCM reinstallation for site code: $SiteCode"
Write-LogMessage -Level Info -Message "Session Mode: $(if ($isInteractive) { 'Interactive' } else { 'Non-Interactive (Scheduled Task/Service)' })"
Write-LogMessage -Level Info -Message "(Step 1 of 3) Attempting reinstall."
try {
    # Configure installation parameters based on site code
    # DDS site installation with simplified parameters
    if ( $SiteCode -eq "DDS") {
        # Note: Commented line shows full parameter set for future reference
        #$proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$SiteCode /mp:SCANZ223 FSP=VOTCZ223" -PassThru -Verbose
        $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$SiteCode" -PassThru -Verbose
        #$proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -PassThru
    }
    # PCI site installation with site code specification
    elseif ( $SiteCode -eq "PCI" ) {
        $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$SiteCode" -PassThru -Verbose    
    }
       
    # Wait for installation process to complete and validate exit code
    $proc.WaitForExit()
    if ( $proc.ExitCode -ne 0 ){
        throw "SCCM install failed with exit code $($proc.exitcode)"
    }
    Write-LogMessage -Level Success -Message "Reinstall complete."
    
    # Monitor service installation - ccmexec service creation can take time
    Write-LogMessage -Level Info -Message "Waiting for service to be installed."
    while ( -not ( Get-Service "ccmexec" -ErrorAction SilentlyContinue )) {
        Start-Sleep -Seconds 120  # Check every 2 minutes
    }
    
    # Wait for service to reach running state before proceeding
    Write-LogMessage -Level Info -Message "Waiting for service to show running."
    while (( Get-Service "ccmexec").Status -ne "Running" ) {
        Start-Sleep -Seconds 120  # Check every 2 minutes
    }
}
Catch{
    Write-LogMessage -Level Error -Message "Install failed. Caught error: $_"
    return $_
}

# -------------------- REGISTER AND RUN CCMEVAL CHECK -------------------- #

# Execute SCCM's built-in evaluation tool to perform initial client validation
Write-LogMessage -Level Info -Message "(Step 2 of 3) Registering CcmEval. Running CcmEval check."
C:\windows\ccm\CcmEval.exe /register  # Register CcmEval scheduled task
C:\windows\ccm\CcmEval.exe /run       # Execute immediate evaluation

# -------------------- RUN UNTIL ALL PASS OR TIMEOUT -------------------- #
Write-LogMessage -Level Info -Message "(Step 3 of 3) Running custom health checks."
Write-LogMessage -Level Info -Message "Pausing for 60 seconds before verifying client is operating correctly."
Start-Sleep -Seconds 60  # Allow time for client initialization after CcmEval

# Retry loop for health validation with configurable attempts
for ( $i = 1; $i -le $maxAttempts; $i++ ) {
    Write-LogMessage -Level Info -Message "---- Health Check Attempt $i ----"

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
if ( -not $success ) {
    Write-LogMessage -Level Error -Message "Health checks did not pass after $maxAttempts attempts."
    return 201  # Custom exit code indicating health check failure
}

# Implicit success return (exit code 0) if all health checks passed

