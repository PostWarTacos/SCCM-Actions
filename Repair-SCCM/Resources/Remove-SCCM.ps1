
<#
.SYNOPSIS
    Removes and cleans up Microsoft SCCM (System Center Configuration Manager) client components.

.DESCRIPTION
    This script performs a comprehensive removal of SCCM client components from a Windows system.
    It attempts a graceful uninstall first, followed by aggressive cleanup if needed.

    The script supports two key parameters for controlling output and execution mode:
    - Interactive: Controls whether the script runs in an interactive PowerShell session (default: $true). When set to $false, the script runs in non-interactive mode (used for scheduled tasks and automation).
    - ConsoleOutput: Controls whether log messages are displayed in the console with color formatting. This is automatically enabled when run by Invoke-SCCMRepair.ps1, or can be set manually.

    Behavior by mode:
    - Interactive ($true): Script runs in an interactive PowerShell session, displays progress, and returns string results. Use for Collection Commander or user shell.
    - Interactive ($false): Script runs in a non-interactive session (scheduled tasks/automation), skips prompts, and will automatically reboot and trigger SCCM reinstall after cleanup. Returns exit codes for automation.

    ConsoleOutput:
    - When $true, log messages are shown in the console with color formatting. When $false, only file logging is performed.
    - Automatically set to $true when run by Invoke-SCCMRepair.ps1.

    The script performs the following actions:
    1. Attempts to restart CcmExec service and remove SMS certificates (quick fix attempt)
    2. Performs standard SCCM uninstall using ccmsetup.exe
    3. Stops and removes SCCM services (CcmExec, CcmSetup)
    4. Terminates SCCM-related processes
    5. Removes SCCM folders and files
    6. Cleans SCCM registry keys
    7. Removes SCCM WMI namespaces
    8. Rebuilds WMI repository (forced cleanup only)
    9. Removes SCCM from Windows Installer MSI database (forced cleanup only)
    10. Reports completion status and any non-critical errors encountered
    11. Configures RunOnce registry key for automatic SCCM reinstall after reboot (non-interactive only)
    12. Initiates system reboot to complete removal and trigger automatic reinstallation (non-interactive only)

.PARAMETER Interactive
    Controls whether the script runs in interactive/manual mode ($true) or non-interactive/automated mode ($false).
    - $true: Prompts for input, manual reboot required, suitable for manual/Collection Commander runs.
    - $false: No prompts, automatic reboot and reinstall, suitable for scheduled tasks and automation.

.PARAMETER ConsoleOutput
    Controls whether log messages are displayed in the console with color formatting.
    - $true: Console output enabled (default when run by Invoke-SCCMRepair.ps1)
    - $false: Only file logging performed

.EXAMPLE
    .\Remove-SCCM.ps1 -Interactive $true
    Runs the complete SCCM removal process interactively, with prompts and manual reboot.

.EXAMPLE
    .\Remove-SCCM.ps1 -Interactive $false
    Runs the SCCM removal process in non-interactive mode, with automatic reboot and reinstall.

.NOTES
    File Name      : Remove-SCCM.ps1
    Version        : 1.3
    Last Updated   : 2025-11-20
    Author         : System Administrator
    Prerequisite   : Administrator privileges required

    WARNING: This script will completely remove SCCM client components.
<<<<<<< HEAD
    When running non-interactively (scheduled task/service), it will automatically
    reboot the system and configure automatic SCCM reinstallation.
    
    INTERACTIVE MODE: Manual execution - run through invoke-command
    NON-INTERACTIVE MODE: Scheduled task/service - automatically reboots and reinstalls SCCM
    
=======
    In non-interactive mode, the system will automatically reboot and configure SCCM reinstallation.

>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
    Prerequisites for automatic reinstall (non-interactive mode):
    - "Reinstall-SCCMTask" scheduled task must exist (created by Create-SCCMScheduledTasks.ps1)
    - SCCM installation files must be available in C:\drivers\ccm\ccmsetup\

    Log files are created at: C:\drivers\ccm\logs\HealthCheck.txt

.OUTPUTS
<<<<<<< HEAD
    Returns exit code 102 if quick fix (step 1) succeeds, otherwise continues full removal.
    In non-interactive mode: System will automatically reboot after cleanup completion.
    All actions are logged to both console and log file.
#>

# ------------------- PARAMETER BLOCK -------------------- #
param(
    [switch]$Invoke
)
# ------------------- FUNCTIONS -------------------- #

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

    # Display console output with appropriate colors for each level (only when running interactively)
    if ($isInteractive) {
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
    
    # Add to health log array for backward compatibility with existing code
    if (-not $healthLog) {
        $healthLog = [System.Collections.ArrayList]@()
    }
    $healthLog.Add($logEntry) | Out-Null
}

Function Stop-ServiceWithTimeout {
=======
    - Interactive PowerShell session: Returns string status for Collection Commander and similar tools.
    - Non-interactive session (scheduled/automated): Returns exit code (0 for success, 1 for failure, 102 for quick fix) for automation and Invoke-SCCMRepair.ps1.
    - All actions are logged to both console (if enabled) and log file.
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [bool]$ConsoleOutput = $false,
    [Parameter(Mandatory = $false)]
    [bool]$Interactive = $true
)

# Detect if script is run via Invoke-SCCMRepair.ps1 and set ConsoleOutput accordingly
if ($MyInvocation.InvocationName -eq 'Invoke-SCCMRepair.ps1' -or $MyInvocation.MyCommand.Name -eq 'Invoke-SCCMRepair.ps1') {
    $ConsoleOutput = $true
}

# ------------------- FUNCTIONS -------------------- #

<#
.SYNOPSIS
    Stops a Windows service with timeout and force termination if needed.
.DESCRIPTION
    Attempts to gracefully stop a service, waits for specified timeout,
    then force kills the process if the service doesn't stop.
.PARAMETER ServiceName
    Name of the Windows service to stop
.PARAMETER TimeoutSeconds
    Maximum time to wait for graceful shutdown (default: 30 seconds)
#>
function Stop-ServiceWithTimeout {
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,

        [int]$TimeoutSeconds = 30
    )
   

    Write-LogMessage -Message "Checking if $ServiceName exists."
    # Check if service exists before attempting any actions
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-LogMessage -Level Warning -Message "Service $ServiceName not found. Skipping stop and kill operations."
        return
    }

    Write-LogMessage -Level Warning -Message "Attempting to stop service: $ServiceName"
    # Attempt to stop if service is running
    if ($service.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 1
        $elapsed++

        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -eq $service -or $service.Status -eq 'Stopped') {
            Write-LogMessage -Level Success -Message "Service $ServiceName stopped successfully."
            Start-Sleep -Seconds 2 # Small delay to ensure processes finish
            break
        }
    }

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -eq 'Stopped') {
        # do nothing
    }
    else {
        # If the service is still running after the timeout, force kill the process
        Write-LogMessage -Level Success -Message "Timeout reached! Forcefully terminating the service process."
        $serviceProcess = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq $ServiceName }
        if ($serviceProcess -and $serviceProcess.ProcessId -ne 0) {
            Stop-Process -Id $serviceProcess.ProcessId -Force -ErrorAction SilentlyContinue
            Write-LogMessage -Level Success -Message "Service process terminated."
        } else {
            Write-LogMessage -Level Warning -Message "Service was already stopped or process not found."
        }
    }
}

<<<<<<< HEAD
=======
<#
.SYNOPSIS
    Writes formatted log messages to console and file with color coding.
.DESCRIPTION
    Creates timestamped log entries with level-specific prefixes and colors.
    Outputs to both console (with colors) and log file simultaneously.
.PARAMETER Level
    Log level: Info, Warning, Error, or Success
.PARAMETER Message
    The message text to log
.PARAMETER LogFile
    Path to log file (default: $healthLogPath\HealthCheck.txt)
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
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes
    $prefix = switch ($Level) {
        "Info"    { "[*]" }
        "Warning" { "[!]" }
        "Error"   { "[!!!]" }
        "Success" { "[+]" }
    }
    
    # Build the log entry
    if (-not $prefix) {
        $logEntry = "[$timestamp] $Message"
    }
    else {
        $logEntry = "[$timestamp] $prefix $Message"
    }

    # Console output with colors (only if ConsoleOutput is true)
    if ($ConsoleOutput) {
        switch ($Level) {
            "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            "Error"   { Write-Host $logEntry -ForegroundColor Red }
            "Success" { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    
    # File output
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        } catch {
            # Use Write-Warning to avoid recursion when logging fails
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
    
    # Add to health log array for backward compatibility
    $healthLog.Add($logEntry) | Out-Null
}


>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
# ------------------- VARIABLES -------------------- #

# Creates an Arraylist which is mutable and easier to manipulate than an array.
# Used for backward compatibility with existing logging systems
$healthLog = [System.Collections.ArrayList]@()

# Error handling variables
$errorCount = 0              # Track non-critical errors that don't stop execution
# $critErrors = $false       # Reserved for future use
$success = $false            # Flag to track if quick fix attempt succeeded

# Directory paths
$healthLogPath = "C:\drivers\ccm\logs"  # Custom log directory for SCCM-related logs

# ------------------- CREATE DIRECTORIES -------------------- #

# Ensure log directory exists before script execution
# Create custom log directory if it doesn't exist (suppressed output for clean execution)
if ( -not ( Test-Path $healthLogPath )) {
    mkdir $healthLogPath | Out-Null
}

# ------------------- MAIN SCRIPT -------------------- #
# 
### The script follows a 12-step process:
# 1. Quick fix attempt - restart service and remove SMS certificates
# 2. Standard SCCM uninstall using ccmsetup.exe
# 3. Force stop and remove SCCM services
# 4. Terminate SCCM-related processes
# 5. Remove SCCM files and folders
# 6. Clean SCCM registry keys
# 7. Remove SCCM WMI namespaces
# 8. Rebuild WMI repository (forced cleanup only)
# 9. Remove SCCM from Windows Installer MSI database (forced cleanup only)
# 10. Completion and error reporting
# 11. Configure RunOnce registry key for automatic SCCM reinstall after reboot (non-interactive only)
# 12. Initiate system reboot to complete SCCM removal and trigger automatic reinstallation (non-interactive only)

<<<<<<< HEAD
Write-LogMessage -message "Attempting repair actions on $(hostname)"
Write-LogMessage -message "Session Mode: $(if ($Invoke) { 'Interactive' } else { 'Non-Interactive (Scheduled Task/Service)' })"

# STEP 1: Quick fix attempt - often resolves SCCM client issues without full removal
# This step tries to fix common SCCM problems by:
# - Stopping the CcmExec service
# - Removing potentially corrupted SMS certificates
# - Restarting the service
# - Testing connectivity to Management Point (MP)
# If successful, script exits early (return code 102)
Write-LogMessage -message "(Step 1 of 12) Stopping CcmExec to remove SMS certs."

$found = Get-Service CcmExec -ErrorAction SilentlyContinue
if ($found) {
    try {
        Stop-ServiceWithTimeout CcmExec
        Write-LogMessage -Level Warning -Message "Removing SMS certs."
        Get-ChildItem Cert:\LocalMachine\SMS | Remove-Item
        Start-Service CcmExec -ErrorAction SilentlyContinue
    
        # Start service
        Start-Sleep -Seconds 10 # Allow some time for the service to start
    
        # Trigger Machine Policy Retrieval & Evaluation Cycle to test MP connectivity
        # Schedule ID {00000000-0000-0000-0000-000000000021} = Machine Policy Retrieval & Evaluation Cycle
        Invoke-CimMethod -Namespace "root\ccm" -ClassName "SMS_Client" -MethodName "TriggerSchedule" -Arguments @{sScheduleID="{00000000-0000-0000-0000-000000000021}"} | Out-Null

        # Check PolicyAgent.log for success indicators
        $policyAgentLogs = "C:\Windows\CCM\Logs\PolicyAgent.log"
        if (Test-Path $policyAgentLogs) {
            try {
                $recentLogs = Get-Content $policyAgentLogs -Tail 50 -ErrorAction Stop
                $patterns = @(
                    "Updated namespace .* successfully",
                    "Successfully received policy assignments from MP",
                    "PolicyAgent successfully processed the policy assignment",
                    "Completed policy evaluation cycle"
                )
                $success = $recentLogs | Select-String -Pattern $patterns
                if ($success) {
                    Write-LogMessage -Level Success -Message "Service restarted successfully and MP contacted. Assuming resolved, ending script."
                    if (-not $Invoke) { 
                        return "Quick Fix Success" # Output for Collection Commander
                    }
                } else {
                    Write-LogMessage -Level Error -Message "Failed to start service. Proceeding with SCCM Client removal."
                }
            } catch {
                Write-LogMessage -Level Warning -Message "Could not read PolicyAgent.log: $($_.Exception.Message). Skipping log check."
            }
        } else {
            Write-LogMessage -Level Warning -Message "PolicyAgent.log not found. Skipping log check."
        }
    } catch {
        if ($_.Exception.Message -match "network|connection|access denied|permission") {
            Write-LogMessage -Level Error -Message "Fatal error encountered: $($_.Exception.Message). Halting execution."
            if (-not $Invoke) {
                return "Fatal Error" # Output for Collection Commander
            }
        } else {
            Write-LogMessage -Level Error -Message "Non-fatal error: $($_.Exception.Message). Proceeding with SCCM Client removal ."
        }
    }
} else {
    Write-LogMessage -Level Warning -Message "CcmExec Service not installed. Proceeding with remnants removal."
}

# STEP 2: Attempt standard SCCM uninstall using built-in ccmsetup.exe
# This is the preferred method as it follows Microsoft's recommended uninstall process
Write-LogMessage -message "(Step 2 of 12) Performing SCCM uninstall."
$standardUninstallSucceeded = $false

if ( Test-Path C:\Windows\ccmsetup\ccmsetup.exe ){
    try {
        Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force
        Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force
        $proc = Start-Process -FilePath "C:\Windows\ccmsetup\ccmsetup.exe" -ArgumentList "/uninstall" -PassThru -Verbose
        $proc.WaitForExit()
        if ( $proc.ExitCode -ne 0 ){
            throw "SCCM uninstall failed with exit code $($proc.exitcode)"
        }
        Write-LogMessage -Level Success -Message "Standard ccmsetup.exe uninstall completed successfully."
        $standardUninstallSucceeded = $true
    }
    catch {
        Write-LogMessage -Level Warning -Message "Standard uninstall failed: $_ - Proceeding with forced cleanup."
        $errorCount++
    }
} else {
    Write-LogMessage -Level Warning -Message "Ccmsetup.exe not found - Proceeding with forced cleanup."
}

# Determine cleanup approach based on standard uninstall success
# If standard uninstall worked: perform gentle cleanup of remaining components
# If standard uninstall failed: perform aggressive forced removal
if ($standardUninstallSucceeded) {
    $cleanupMode = "cleanup"
    $cleanupDescription = "Performing post-uninstall cleanup"
    if (-not $Invoke) {
        Write-Output "Standard Uninstall Succeeded."  # Output for Collection Commander
    }
} else {
    $cleanupMode = "forced uninstall"
    $cleanupDescription = "Performing forced uninstall"
    if (-not $Invoke) {
        Write-Output "Standard Uninstall Failed. Proceeding with forced uninstall."  # Output for Collection Commander
    }
}

Write-LogMessage -message "$cleanupDescription of any remaining SCCM components..."

# STEP 3: Remove SCCM Windows services
# - ccmexec: Main SCCM client service ("SMS Agent Host")
# - ccmsetup: SCCM client installation/maintenance service
Write-LogMessage -message "(Step 3 of 12) Stopping and removing CcmExec and CcmSetup services ($cleanupMode)."
$services = @(
    "ccmexec",
    "ccmsetup"
)
foreach ( $service in $services ){
    if ( get-service $service -ErrorAction SilentlyContinue ){
=======
try {
    # Only clear screen when running interactively (not as scheduled task)
    if ($Interactive) {
        Clear-Host
    }

    Write-LogMessage -Level Info -Message "Attempting repair actions on $(hostname)"
    Write-LogMessage -Level Info -Message "Session Mode: $(if ($Interactive) { 'Interactive' } else { 'Non-Interactive (Scheduled Task/Service)' })"

    # STEP 1: Quick fix attempt - often resolves SCCM client issues without full removal
    # This step tries to fix common SCCM problems by:
    # - Stopping the CcmExec service
    # - Removing potentially corrupted SMS certificates
    # - Restarting the service
    # - Testing connectivity to Management Point (MP)
    # If successful, script exits early (return code 102)
    Write-LogMessage -Level Info -Message "(Step 1 of 12) Stopping CcmExec to remove SMS certs."
    $found = Get-Service CcmExec -ErrorAction SilentlyContinue
    if ( $found ){
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
        try {
            Stop-ServiceWithTimeout CcmExec
            Write-LogMessage -Level Warning -Message "Removing SMS certs."
            Get-ChildItem Cert:\LocalMachine\SMS | Remove-Item
            Start-Service CcmExec -ErrorAction SilentlyContinue
        
            # Start service
            Start-Sleep -Seconds 10 # Allow some time for the service to start
        
            # Trigger Machine Policy Retrieval & Evaluation Cycle to test MP connectivity
            # Schedule ID {00000000-0000-0000-0000-000000000021} = Machine Policy Retrieval & Evaluation Cycle
            Invoke-CimMethod -Namespace "root\ccm" -ClassName "SMS_Client" -MethodName "TriggerSchedule" -Arguments @{sScheduleID="{00000000-0000-0000-0000-000000000021}"} | Out-Null
            
            # Check PolicyAgent.log for success indicators
            $policyAgentLogs = "C:\Windows\CCM\Logs\PolicyAgent.log"
            $recentLogs = Get-Content $policyAgentLogs -Tail 50
            
            # Patterns that indicate successful SCCM client operation
            $patterns = @(
                "Updated namespace .* successfully",
                "Successfully received policy assignments from MP",
                "PolicyAgent successfully processed the policy assignment",
                "Completed policy evaluation cycle"
            )
                                     
            $success = $recentLogs | Select-String -Pattern $patterns
            
            # Announce success/fail
            if ( $success ) {
                Write-LogMessage -Level Success -Message "Service restarted successfully and MP contacted. Assuming resolved, ending script."
                return 102
            } else {
                Write-LogMessage -Level Error -Message "Failed to start service. Continuing with SCCM Client removal and reinstall."
            }   
        }
        catch {
               Write-LogMessage -Level Error -Message "Failed to start service. Continuing with SCCM Client removal and reinstall."
        }
    } Else {
        Write-LogMessage -Level Warning -Message "CcmExec Service not installed. Continuing with SCCM Client removal and reinstall."
    }

    # STEP 2: Attempt standard SCCM uninstall using built-in ccmsetup.exe
    # This is the preferred method as it follows Microsoft's recommended uninstall process
    Write-LogMessage -Level Info -Message "(Step 2 of 12) Performing SCCM uninstall."
    $standardUninstallSucceeded = $false

    if ( Test-Path C:\Windows\ccmsetup\ccmsetup.exe ){
        try {
            Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force
            Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force
            $proc = Start-Process -FilePath "C:\Windows\ccmsetup\ccmsetup.exe" -ArgumentList "/uninstall" -PassThru -Verbose
            $proc.WaitForExit()
            if ( $proc.ExitCode -ne 0 ){
                throw "SCCM uninstall failed with exit code $($proc.exitcode)"
            }
            Write-LogMessage -Level Success -Message "Standard ccmsetup.exe uninstall completed successfully."
            $standardUninstallSucceeded = $true
        }
        catch {
            Write-LogMessage -Level Warning -Message "Standard uninstall failed: $_ - Proceeding with forced cleanup."
            $errorCount++
        }
<<<<<<< HEAD
    } else{
        Write-LogMessage -Level Warning -Message "$service service not found."
    }
    if (-not $Invoke) {
        Write-Output "Step 3 - Service Removal Completed" # Output for Collection Commander
    }        
}

# STEP 4: Terminate any remaining SCCM-related processes
# Searches for processes by name pattern (*ccm*) and by loaded modules
# This ensures no SCCM processes are holding files/registry keys that need cleanup
Write-LogMessage -message "(Step 4 of 12) Killing all tasks related to SCCM ($cleanupMode)."
# Define SCCM file system locations to be removed
$files = @(
    "C:\Windows\CCM",          # Main SCCM client directory
    "C:\Windows\ccmcache",     # SCCM client cache directory
    "C:\Windows\ccmsetup",     # SCCM installation files
    "C:\Windows\SMSCFG.ini"    # SCCM configuration file
)
foreach ( $file in $files ){
    try {
        if (Test-Path $file) {
            $proc = Get-Process | Where-Object {
                $_.ProcessName -like "*ccm*" -or
                ($_.Modules -and $_.Modules.FileName -like "$file*")
            } -ErrorAction SilentlyContinue
            if ($proc) {
                try {
                    Stop-Process $proc.Id -Force -ErrorAction SilentlyContinue
                    Write-LogMessage -Level Success -Message "$($proc.ProcessName) killed. Process was tied to $file."
                } catch {
                    if ($_.Exception.Message -match "network|connection|access denied|permission") {
                        Write-LogMessage -Level Error -Message "Fatal error encountered: $($_.Exception.Message). Halting execution."
                        exit 2
                    } else {
                        Write-LogMessage -Level Error -Message "Failed to kill $($proc.ProcessName) process. Continuing script but may cause issues."
                        $errorCount++
                    }
                }
            } else {
                Write-LogMessage -Level Warning -Message "Could not find a process tied to $file."
            }
        } else {
            Write-LogMessage -Level Warning -Message "$file not found. Skipping process check."
        }
    } catch {
        if ($_.Exception.Message -match "network|connection|access denied|permission") {
            Write-LogMessage -Level Error -Message "Fatal error encountered: $($_.Exception.Message). Halting execution."
            exit 2
        } else {
            Write-LogMessage -Level Warning -Message "Error checking processes for $file. Continuing script."
        }
    }
    if (-not $Invoke) {
        Write-Output "Step 4 - Process Termination Completed" # Output for Collection Commander
=======
    } else {
        Write-LogMessage -Level Warning -Message "Ccmsetup.exe not found - Proceeding with forced cleanup."
    }

    # Determine cleanup approach based on standard uninstall success
    # If standard uninstall worked: perform gentle cleanup of remaining components
    # If standard uninstall failed: perform aggressive forced removal
    if ($standardUninstallSucceeded) {
        $cleanupMode = "cleanup"
        $cleanupDescription = "Performing post-uninstall cleanup"
    } else {
        $cleanupMode = "forced uninstall"
        $cleanupDescription = "Performing forced uninstall"
    }

    Write-LogMessage -Level Warning -Message "$cleanupDescription of any remaining SCCM components..."

    # STEP 3: Remove SCCM Windows services
    # - ccmexec: Main SCCM client service ("SMS Agent Host")
    # - ccmsetup: SCCM client installation/maintenance service
    Write-LogMessage -Level Info -Message "(Step 3 of 12) Stopping and removing CcmExec and CcmSetup services ($cleanupMode)."
    $services = @(
        "ccmexec",
        "ccmsetup"
    )
    foreach ( $service in $services ){
        if ( get-service $service -ErrorAction SilentlyContinue ){
            try {
                Stop-ServiceWithTimeout $service
                & sc.exe delete $service
                Write-LogMessage -Level Success -Message "$service service found and removed."
            }
            catch {
                Write-LogMessage -Level Error -Message "Failed to stop and remove $service service. Continuing script but may cause issues."
                $errorCount++
            }
        } else{
            Write-LogMessage -Level Warning -Message "$service service not found."
        }        
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
    }

<<<<<<< HEAD
# STEP 5: Remove SCCM files and directories
# Uses takeown to gain ownership of files before deletion (handles permission issues)
Write-LogMessage -message "(Step 5 of 12) Deleting all SCCM folders and files ($cleanupMode)."
foreach ( $file in $files ){
    if (Test-Path $file) {
        try {
            $null = takeown /F $file /R /A /D Y 2>&1
            $ConfirmPreference = 'None'
            Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogMessage -Level Success -Message "$file found and removed."
        } catch {
            if ($_.Exception.Message -match "network|connection|access denied|permission") {
                Write-LogMessage -Level Error -Message "Fatal error encountered: $($_.Exception.Message). Halting execution."
                exit 2
            } else {
                Write-LogMessage -Level Error -Message "Failed to remove $file file(s): $($_.Exception.Message). Continuing script but may cause issues."
                $errorCount++
            }
        }
    } else {
        Write-LogMessage -Level Warning -Message "$file not found. Skipping removal."
    }
    if (-not $Invoke) {
        Write-Output "Step 5 - File Removal Completed" # Output for Collection Commander
    }
}

# STEP 6: Remove SCCM registry keys
# This removes all traces of SCCM from the Windows registry
Write-LogMessage -message "(Step 6 of 12) Deleting all SCCM reg keys ($cleanupMode)."

# Define all SCCM-related registry paths
$keys= @(
    # Main SCCM registry keys
    "HKLM:\Software\Microsoft\CCM",
    "HKLM:\Software\Microsoft\SMS",
    "HKLM:\Software\Microsoft\ccmsetup",
    
    # 32-bit compatibility keys on 64-bit systems
    "HKLM:\Software\Wow6432Node\Microsoft\CCM",
    "HKLM:\Software\Wow6432Node\Microsoft\SMS",
    "HKLM:\Software\Wow6432Node\Microsoft\ccmsetup",
    
    # Windows service registry entries
    "HKLM:\System\CurrentControlSet\Services\CcmExec",
    "HKLM:\System\CurrentControlSet\Services\prepdrvr",      # SCCM driver
    "HKLM:\System\CurrentControlSet\Services\ccmsetup",
    
    # Event log entries
    "HKLM:\System\CurrentControlSet\Services\eventlog\Application\Configuration Manager Agent",
    
    # SMS certificates
    "HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*"
)
foreach ( $key in $keys ){
    if (Test-Path $key) {
        try {
            Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogMessage -Level Success -Message "$key found and removed."
        } catch {
            if ($_.Exception.Message -match "network|connection|access denied|permission") {
                Write-LogMessage -Level Error -Message "Fatal error encountered: $($_.Exception.Message). Halting execution."
                exit 2
            } else {
                Write-LogMessage -Level Error -Message "Failed to remove $key reg key: $($_.Exception.Message). Continuing script but may cause issues."
                $errorCount++
            }
        }
    } else {
        Write-LogMessage -Level Warning -Message "Could not find $key. Skipping removal."
    }
    if (-not $Invoke) {
        Write-Output "Step 6 - Reg Key Removal Completed" # Output for Collection Commander
    }
}

# STEP 7: Remove SCCM WMI (Windows Management Instrumentation) namespaces
# These namespaces contain SCCM client configuration and status information
# Removing them ensures complete cleanup of SCCM client data structures
Write-LogMessage -message "(Step 7 of 12) Remove SCCM namespaces from WMI repo ($cleanupMode)."
try {
    # Remove main CCM namespace (Configuration Manager Client)
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    
    # Remove VDI-specific CCM namespace (Virtual Desktop Infrastructure)
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    
    # Remove SMS Device Management namespace
    Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    
    # Remove legacy SMS namespace from cimv2
    Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-LogMessage -Level Success -Message "Namespace(s) found and removed."
    if (-not $Invoke) {
        Write-Output "Step 7 - Namespace Removal Completed" # Output for Collection Commander
    }
}
catch {
    Write-LogMessage -Level Error -Message "Failed to remove namespace(s). Continuing script but may cause issues."
    $errorCount++
}

# STEP 8: Rebuild WMI repository (forced cleanup only)
# After failed uninstall attempts, WMI can be corrupted
# Rebuilding ensures clean state for SCCM reinstallation
if (-not $standardUninstallSucceeded) {
    Write-LogMessage -message "(Step 8 of 12) Rebuilding WMI repository."
    try {
        Write-LogMessage -Level Warning -Message "Stopping WMI service..."
        Stop-Service -Name winmgmt -Force -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        Write-LogMessage -Level Info -Message "Resetting WMI repository..."
        $wmgmtResult = Start-Process -FilePath "winmgmt.exe" -ArgumentList "/resetrepository" -Wait -PassThru -WindowStyle Hidden
        
        if ($wmgmtResult.ExitCode -eq 0) {
            Write-LogMessage -Level Success -Message "WMI repository reset successfully."
            if (-not $Invoke) {
                Write-Output "Step 8 - WMI Reset Success." # Output for Collection Commander
            }
        } else {
            Write-LogMessage -Level Warning -Message "WMI reset returned exit code: $($wmgmtResult.ExitCode). Attempting to continue..."
        }
        
        Write-LogMessage -Level Info -Message "Starting WMI service..."
        Start-Service -Name winmgmt -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        # Verify WMI is working
        $testWMI = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($testWMI) {
            Write-LogMessage -Level Success -Message "WMI is functioning correctly after rebuild."
        } else {
            Write-LogMessage -Level Warning -Message "WMI test failed. May require system reboot."
        }
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to rebuild WMI repository: $($_.Exception.Message)"
        Write-LogMessage -Level Warning -Message "Continuing cleanup. WMI issues may require manual intervention."
        if (-not $Invoke) {
            Write-Output "Step 8 - WMI Reset Failed. Proceeding with removal." # Output for Collection Commander
        }
        $errorCount++
    }
} else {
    Write-LogMessage -Level Info -Message "(Step 8 of 12) Skipping WMI rebuild (post-uninstall cleanup)."
}

# STEP 9: Remove SCCM from Windows Installer database (forced cleanup only)
# After failed uninstalls, MSI database may still have SCCM product registrations
# This prevents the installer from attempting repairs instead of fresh installs
if (-not $forceCleanup) {
    Write-LogMessage -Level Info -Message "(Step 9 of 12) Removing SCCM from Windows Installer database."
    try {
        # Get all SCCM-related products from MSI database
        Write-LogMessage -Level Info -Message "Searching for SCCM products in MSI database..."
        $sccmProducts = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -like "*Configuration Manager*" -or 
            $_.Name -like "*CCM*" -or
            $_.IdentifyingNumber -eq "{987AABAD-F544-404E-86C6-215EAFBEB7C0}"
        }
        
        if ($sccmProducts) {
            foreach ($product in $sccmProducts) {
                Write-LogMessage -Level Info -Message "Uninstalling '$($product.Name)' (Product Code: $($product.IdentifyingNumber)) from MSI database..."
=======
    # STEP 4: Terminate any remaining SCCM-related processes
    # Searches for processes by name pattern (*ccm*) and by loaded modules
    # This ensures no SCCM processes are holding files/registry keys that need cleanup
    Write-LogMessage -Level Info -Message "(Step 4 of 12) Killing all tasks related to SCCM ($cleanupMode)."
    # Define SCCM file system locations to be removed
    $files = @(
        "C:\Windows\CCM",          # Main SCCM client directory
        "C:\Windows\ccmcache",     # SCCM client cache directory
        "C:\Windows\ccmsetup",     # SCCM installation files
        "C:\Windows\SMSCFG.ini"    # SCCM configuration file
    )
    foreach ( $file in $files ){
        try {
            $proc = Get-Process | Where-Object { 
                $_.ProcessName -like "*ccm*" -or 
                ($_.Modules -and $_.Modules.FileName -like "$file*") 
            } -ErrorAction SilentlyContinue
            
            if ($proc){
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
                try {
                    Stop-Process $proc.Id -Force -ErrorAction SilentlyContinue
                    Write-LogMessage -Level Success -Message "$($proc.ProcessName) killed. Process was tied to $file."
                }
                catch {
                    Write-LogMessage -Level Error -Message "Failed to kill $($proc.ProcessName) process. Continuing script but may cause issues."
                    $errorCount++
                }
            } else{
                Write-LogMessage -Level Warning -Message "Could not find a process tied to $file."
            }
        } catch {
            Write-LogMessage -Level Warning -Message "Error checking processes for $file. Continuing script."
        }
        if (-not $Invoke) {
            Write-Output "Step 9 - MSI Database Cleanup Completed." # Output for Collection Commander
        }
    }
<<<<<<< HEAD
    catch {
        Write-LogMessage -Level Error -Message "Failed to query/remove MSI database entries: $($_.Exception.Message)"
        Write-LogMessage -Level Warning -Message "Continuing cleanup. MSI database may still contain SCCM entries."
        if (-not $Invoke) {
            Write-Output "Step 9 - MSI Database Cleanup Failed. Proceeding with removal." # Output for Collection Commander
        }
        $errorCount++
=======

    # STEP 5: Remove SCCM files and directories
    # Uses takeown to gain ownership of files before deletion (handles permission issues)
    Write-LogMessage -Level Info -Message "(Step 5 of 12) Deleting all SCCM folders and files ($cleanupMode)."
    foreach ( $file in $files ){
        if ( Test-Path $file ){
            try {
                $null = takeown /F $file /R /A /D Y 2>&1
                $ConfirmPreference = 'None'
                Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue
                Write-LogMessage -Level Success -Message "$file found and removed."
            }
            catch {
                Write-LogMessage -Level Error -Message "Failed to remove $file file(s). Continuing script but may cause issues."
                $errorCount++
            }
        } else{
            Write-LogMessage -Level Warning -Message "$file not found."
        }
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
    }

<<<<<<< HEAD
### STEP 10: Final completion and error reporting
# Report overall success and any non-critical errors encountered
Write-LogMessage -Level Success -Message "(Step 10 of 12) $cleanupDescription completed successfully."
if( $Invoke ) {
    Write-LogMessage -Level Info -Message "Steps 11 and 12 will be skipped in interactive mode. They are executed via the parent script, Invoke-SCCMRepair.ps1."
}
=======
    # STEP 6: Remove SCCM registry keys
    # This removes all traces of SCCM from the Windows registry
    Write-LogMessage -Level Info -Message "(Step 6 of 12) Deleting all SCCM reg keys ($cleanupMode)."
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d

    # Define all SCCM-related registry paths
    $keys= @(
        # Main SCCM registry keys
        "HKLM:\Software\Microsoft\CCM",
        "HKLM:\Software\Microsoft\SMS",
        "HKLM:\Software\Microsoft\ccmsetup",
        
        # 32-bit compatibility keys on 64-bit systems
        "HKLM:\Software\Wow6432Node\Microsoft\CCM",
        "HKLM:\Software\Wow6432Node\Microsoft\SMS",
        "HKLM:\Software\Wow6432Node\Microsoft\ccmsetup",
        
        # Windows service registry entries
        "HKLM:\System\CurrentControlSet\Services\CcmExec",
        "HKLM:\System\CurrentControlSet\Services\prepdrvr",      # SCCM driver
        "HKLM:\System\CurrentControlSet\Services\ccmsetup",
        
        # Event log entries
        "HKLM:\System\CurrentControlSet\Services\eventlog\Application\Configuration Manager Agent",
        
        # SMS certificates
        "HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*"
    )
    foreach ( $key in $keys ){
        if( Test-Path $KEY ){
            try {
                Remove-Item $KEY -Recurse -Force -ErrorAction SilentlyContinue
                Write-LogMessage -Level Success -Message "$KEY found and removed."
            }
            catch {
                Write-LogMessage -Level Error -Message "Failed to remove $key reg key. Continuing script but may cause issues."
                $errorCount++
            }
        } Else { 
            Write-LogMessage -Level Warning -Message "Could not find $KEY."
        }
    }

<<<<<<< HEAD
# STEP 11: Configure post-reboot SCCM reinstallation (only when non-interactive)
# When running as scheduled task, set up automatic SCCM reinstall after reboot
<#  COMMENTED OUT - NOT READY FOR PRODUCTION USE YET
if (-not $Invoke) {
    Write-LogMessage -Level Info -Message "(Step 11 of 12) Configuring post-reboot SCCM reinstallation (non-interactive mode only)."
=======
    # STEP 7: Remove SCCM WMI (Windows Management Instrumentation) namespaces
    # These namespaces contain SCCM client configuration and status information
    # Removing them ensures complete cleanup of SCCM client data structures
    Write-LogMessage -Level Info -Message "(Step 7 of 12) Remove SCCM namespaces from WMI repo ($cleanupMode)."
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
    try {
        # Remove main CCM namespace (Configuration Manager Client)
        Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        
        # Remove VDI-specific CCM namespace (Virtual Desktop Infrastructure)
        Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        
        # Remove SMS Device Management namespace
        Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        
        # Remove legacy SMS namespace from cimv2
        Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-LogMessage -Level Success -Message "Namespace(s) found and removed."
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to remove namespace(s). Continuing script but may cause issues."
        $errorCount++
    }

    # STEP 8: Rebuild WMI repository (forced cleanup only)
    # After failed uninstall attempts, WMI can be corrupted
    # Rebuilding ensures clean state for SCCM reinstallation
    if ($forceCleanup) {
        Write-LogMessage -Level Info -Message "(Step 8 of 12) Rebuilding WMI repository."
        try {
            Write-LogMessage -Level Warning -Message "Stopping WMI service..."
            Stop-Service -Name winmgmt -Force -ErrorAction Stop
            Start-Sleep -Seconds 3
            
            Write-LogMessage -Level Info -Message "Resetting WMI repository..."
            $wmgmtResult = Start-Process -FilePath "winmgmt.exe" -ArgumentList "/resetrepository" -Wait -PassThru -WindowStyle Hidden
            
            if ($wmgmtResult.ExitCode -eq 0) {
                Write-LogMessage -Level Success -Message "WMI repository reset successfully."
            } else {
                Write-LogMessage -Level Warning -Message "WMI reset returned exit code: $($wmgmtResult.ExitCode). Attempting to continue..."
            }
            
            Write-LogMessage -Level Info -Message "Starting WMI service..."
            Start-Service -Name winmgmt -ErrorAction Stop
            Start-Sleep -Seconds 3
            
            # Verify WMI is working
            $testWMI = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($testWMI) {
                Write-LogMessage -Level Success -Message "WMI is functioning correctly after rebuild."
            } else {
                Write-LogMessage -Level Warning -Message "WMI test failed. May require system reboot."
            }
        }
        catch {
            Write-LogMessage -Level Error -Message "Failed to rebuild WMI repository: $($_.Exception.Message)"
            Write-LogMessage -Level Warning -Message "Continuing cleanup. WMI issues may require manual intervention."
            $errorCount++
        }
    } else {
        Write-LogMessage -Level Info -Message "(Step 8 of 12) Skipping WMI rebuild (post-uninstall cleanup)."
    }

    # STEP 9: Remove SCCM from Windows Installer database (forced cleanup only)
    # After failed uninstalls, MSI database may still have SCCM product registrations
    # This prevents the installer from attempting repairs instead of fresh installs
    if ($forceCleanup) {
        Write-LogMessage -Level Info -Message "(Step 9 of 12) Removing SCCM from Windows Installer database."
        try {
            # Get all SCCM-related products from MSI database
            Write-LogMessage -Level Info -Message "Searching for SCCM products in MSI database..."
            $sccmProducts = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -like "*Configuration Manager*" -or 
                $_.Name -like "*CCM*" -or
                $_.IdentifyingNumber -eq "{987AABAD-F544-404E-86C6-215EAFBEB7C0}"
            }
            
            if ($sccmProducts) {
                foreach ($product in $sccmProducts) {
                    Write-LogMessage -Level Info -Message "Uninstalling '$($product.Name)' (Product Code: $($product.IdentifyingNumber)) from MSI database..."
                    try {
                        $uninstallResult = $product.Uninstall()
                        if ($uninstallResult.ReturnValue -eq 0) {
                            Write-LogMessage -Level Success -Message "Removed '$($product.Name)' from MSI database."
                        } else {
                            Write-LogMessage -Level Warning -Message "Uninstall returned code: $($uninstallResult.ReturnValue). Product may still be partially registered."
                        }
                    }
                    catch {
                        Write-LogMessage -Level Warning -Message "Failed to uninstall '$($product.Name)': $($_.Exception.Message)"
                    }
                }
            } else {
                Write-LogMessage -Level Info -Message "No SCCM products found in MSI database."
            }
        }
        catch {
            Write-LogMessage -Level Error -Message "Failed to query/remove MSI database entries: $($_.Exception.Message)"
            Write-LogMessage -Level Warning -Message "Continuing cleanup. MSI database may still contain SCCM entries."
            $errorCount++
        }
    } else {
        Write-LogMessage -Level Info -Message "(Step 9 of 12) Skipping MSI database cleanup (post-uninstall cleanup)."
    }

    ### STEP 10: Final completion and error reporting
    # Report overall success and any non-critical errors encountered
    Write-LogMessage -Level Success -Message "(Step 10 of 12) $cleanupDescription completed successfully."
    if( $Interactive ) {
        Write-LogMessage -Level Info -Message "Steps 11 and 12 will be skipped in interactive mode. They are executed via the parent script, Invoke-SCCMRepair.ps1."
    }

    # Report any non-critical errors that occurred during execution
    # These errors don't prevent the script from completing but should be reviewed
    if ( $errorCount -gt 0 ){
        Write-LogMessage -Level Warning -Message "There were $errorCount non-critical errors."
    }

    # STEP 11: Configure post-reboot SCCM reinstallation (only when non-interactive)
    # When running as scheduled task, set up automatic SCCM reinstall after reboot
    if (-not $Interactive) {
        Write-LogMessage -Level Info -Message "(Step 11 of 12) Configuring post-reboot SCCM reinstallation (non-interactive mode only)."
        try {
            # Create RunOnce registry entry to trigger the Reinstall-SCCMTask scheduled task after reboot
            # This ensures SCCM gets reinstalled automatically when the system comes back online
            $runOnceCommand = 'schtasks.exe /Run /TN "Reinstall-SCCMTask"'
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "TriggerSCCMReinstall" -Value $runOnceCommand -Type String
            Write-LogMessage -Level Success -Message "RunOnce registry key created to trigger SCCM reinstall after reboot."
        } catch {
            Write-LogMessage -Level Error -Message "Failed to create RunOnce registry key: $_"
            $errorCount++
        }
    }

    # STEP 12: Initiate system reboot (only when non-interactive)
    # When running as scheduled task, automatically reboot to complete SCCM removal and trigger reinstall
    if (-not $Interactive) {
        Write-LogMessage -Level Info -Message "(Step 12 of 12) Initiating system reboot to complete SCCM removal process (non-interactive mode only)."
        Write-LogMessage -Level Warning -Message "System will reboot. SCCM will be automatically reinstalled after reboot."
        
        # Provide brief delay to allow log messages to be written and visible
        Start-Sleep -Seconds 5
        
        # Force reboot with 0-second delay for unattended operation
        # shutdown.exe /r /t 0 /f
    }

    # Return appropriate exit code based on removal results
    if ($MyInvocation.InvocationName -eq 'Invoke-SCCMRepair.ps1' -or $MyInvocation.MyCommand.Name -eq 'Invoke-SCCMRepair.ps1' -or $env:RUNNING_SCHEDULEDTASK) {
        if ($errorCount -gt 5) {
            Write-LogMessage -Level Error -Message "Removal completed with $errorCount errors. This may indicate removal failure."
            exit 1
        } else {
            Write-LogMessage -Level Success -Message "Full SCCM removal completed successfully. $errorCount non-critical errors."
            exit 0
        }
    } else {
        if ($errorCount -gt 5) {
            Write-LogMessage -Level Error -Message "Removal completed with $errorCount errors. This may indicate removal failure."
            return "FAILED: SCCM removal encountered $errorCount errors. Review logs on local machine."
        } else {
            Write-LogMessage -Level Success -Message "Full SCCM removal completed successfully. $errorCount non-critical errors."
            return "SUCCESS: SCCM removal completed. $errorCount non-critical errors."
        }
    }
} catch {
    Write-LogMessage -Level Error -Message "Exception occurred: $_"
    if ($MyInvocation.InvocationName -eq 'Invoke-SCCMRepair.ps1' -or $MyInvocation.MyCommand.Name -eq 'Invoke-SCCMRepair.ps1' -or $env:RUNNING_SCHEDULEDTASK) {
        exit 1
    } else {
        return "FAILED: Exception occurred during SCCM removal. Review logs on local machine."
    }
}
#>

<<<<<<< HEAD
<#  COMMENTED OUT - NOT READY FOR PRODUCTION USE YET
# STEP 12: Initiate system reboot (only when non-interactive)
# When running as scheduled task, automatically reboot to complete SCCM removal and trigger reinstall
if (-not $isInteractive) {
    Write-LogMessage -Level Info -Message "(Step 12 of 12) Initiating system reboot to complete SCCM removal process (non-interactive mode only)."
    Write-LogMessage -Level Warning -Message "System will reboot. SCCM will be automatically reinstalled after reboot."
    
    # Provide brief delay to allow log messages to be written and visible
    Start-Sleep -Seconds 5
    
    # Force reboot with 0-second delay for unattended operation
    # shutdown.exe /r /t 0 /f
}
#>

# Return appropriate exit code based on removal results
if ( $Invoke ) {
    # Non-Collection Commander: preserve previous logic (multiple returns)
    if ($errorCount -gt 5) {
        Write-LogMessage -Level Error -Message "Removal completed with $errorCount errors. This may indicate removal failure."
        return 1
    } else {
        Write-LogMessage -Level Success -Message "Full SCCM removal completed successfully. $errorCount errors."
        return 0
    }
} else {
    # Collection Commander: Only return one status at end
    if ($errorCount -gt 5) {
        Write-LogMessage -Level Error -Message "Removal completed with $errorCount errors. This may indicate removal failure."
        return "Removal Failed. $errorCount errors."
    } else {
        Write-LogMessage -Level Success -Message "Full SCCM removal completed successfully. $errorCount errors"
        return "Removal Succeeded. $errorCount errors."
    }
}

=======
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
