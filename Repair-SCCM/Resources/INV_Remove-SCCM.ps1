<#
.SYNOPSIS
    Removes and cleans up Microsoft SCCM (System Center Configuration Manager) client components.

.DESCRIPTION
    This script performs a comprehensive removal of SCCM client components from a Windows system.
    It attempts a graceful uninstall first, followed by aggressive cleanup if needed.
    
    The script performs the following actions:
    1. Attempts to restart CcmExec service and remove SMS certificates (quick fix attempt)
    2. Performs standard SCCM uninstall using ccmsetup.exe
    3. Stops and removes SCCM services (CcmExec, CcmSetup)
    4. Terminates SCCM-related processes
    5. Removes SCCM folders and files
    6. Cleans SCCM registry keys
    7. Removes SCCM WMI namespaces
    8. Reports completion status and any non-critical errors encountered

.PARAMETER None
    This script does not accept parameters.

.EXAMPLE
    .\Remove-SCCM.ps1
    
    Runs the complete SCCM removal process with detailed logging.

.NOTES
    Author: [Your Name]
    Version: 1.0
    Requires: PowerShell 5.0+, Administrator privileges
    
    WARNING: This script will completely remove SCCM client components.
    Ensure you have a way to reinstall the SCCM client if needed.
    
    Log files are created at: C:\drivers\ccm\logs\HealthCheck.txt

.OUTPUTS
    Returns exit code 102 if quick fix (step 1) succeeds, otherwise continues full removal.
    All actions are logged to both console and log file.
#>

#Requires -Version 5.0
#Requires -RunAsAdministrator

# ------------------- FUNCTIONS -------------------- #

<#
.SYNOPSIS
    Prompts for user input with a timeout and optional validation.
.DESCRIPTION
    Creates a background job to handle user input with a specified timeout.
    Exits the script if no input is provided within the timeout period.
.PARAMETER Prompt
    The message to display to the user
.PARAMETER TimeoutSeconds
    Number of seconds to wait for input (default: 10)
.PARAMETER ValidValues
    Array of acceptable input values for validation
#>
function Get-UserInputWithTimeout {
    param(
        [string]$Prompt,
        [int]$TimeoutSeconds = 10,
        [string[]]$ValidValues = @()
    )
    
    Write-LogMessage -Level Warning -Message "$Prompt"
    Write-LogMessage -Level Error -Message "Script will exit if no input provided within $TimeoutSeconds seconds"
    
    $job = Start-Job -ScriptBlock {
        param($Prompt)
        Read-Host $Prompt
    } -ArgumentList $Prompt
    
    $completed = Wait-Job $job -Timeout $TimeoutSeconds
    
    if ($completed) {
        $result = Receive-Job $job
        Remove-Job $job
        
        # If no input provided (empty string or null), exit script
        if ([string]::IsNullOrWhiteSpace($result)) {
            Write-LogMessage -Level Error -Message "No input provided. Exiting script."
            exit 1
        }
        
        # Validate against allowed values if provided
        if ($ValidValues.Count -gt 0 -and $result.ToUpper().Trim() -notin $ValidValues) {
            Write-LogMessage -Level Error -Message "Invalid input: $result"
            return $null  # Invalid input - allows retry
        }
        
        return $result.ToUpper().Trim()
    } else {
        Stop-Job $job
        Remove-Job $job
        Write-LogMessage -Level Error -Message "Timeout reached. No input provided. Exiting script."
        exit 1
    }
}

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
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,

        [int]$TimeoutSeconds = 30
    )

    Write-LogMessage -Level Warning -Message "Attempting to stop service: $ServiceName"
    
    # Attempt to stop if service is running
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ( $service.Status -eq 'Running' ){
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    $elapsed = 0
    while ( $elapsed -lt $TimeoutSeconds ) {
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
    if ( $null -eq $service -or $service.Status -eq 'Stopped' ) {
        # do nothing
    }
    else {
        # If the service is still running after the timeout, force kill the process
        Write-LogMessage -Level Success -Message "Timeout reached! Forcefully terminating the service process."
        $serviceProcess = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq $ServiceName }
        if ( $serviceProcess -and $serviceProcess.ProcessId -ne 0 ) {
            Stop-Process -Id $serviceProcess.ProcessId -Force -ErrorAction SilentlyContinue
            Write-LogMessage -Level Success -Message "Service process terminated."
        } else {
            Write-LogMessage -Level Warning -Message "Service was already stopped or process not found."
        }
    }
}

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

    # Console output with colors
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
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
# The script follows a 9-step process:
# 1. Quick fix attempt - restart service and remove SMS certificates
# 2. Standard SCCM uninstall using ccmsetup.exe
# 3. Force stop and remove SCCM services
# 4. Terminate SCCM-related processes
# 5. Remove SCCM files and folders
# 6. Clean SCCM registry keys
# 7. Remove SCCM WMI namespaces
# 8-9. Completion and error reporting

Clear-Host

Write-LogMessage -Level Info -Message "Attempting repair actions on $(hostname)"

# STEP 1: Quick fix attempt - often resolves SCCM client issues without full removal
# This step tries to fix common SCCM problems by:
# - Stopping the CcmExec service
# - Removing potentially corrupted SMS certificates
# - Restarting the service
# - Testing connectivity to Management Point (MP)
# If successful, script exits early (return code 102)
Write-LogMessage -Level Info -Message "(Step 1 of 9) Stopping CcmExec to remove SMS certs."
$found = Get-Service CcmExec -ErrorAction SilentlyContinue
if ( $found ){
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
Write-LogMessage -Level Info -Message "(Step 2 of 9) Performing SCCM uninstall."
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
        Write-LogMessage -Level Warning -Message "Standard uninstall failed: $_ - Proceeding with force cleanup."
        $errorCount++
    }
} else {
    Write-LogMessage -Level Warning -Message "Ccmsetup.exe not found - Proceeding with force cleanup."
}

# Determine cleanup approach based on standard uninstall success
# If standard uninstall worked: perform gentle cleanup of remaining components
# If standard uninstall failed: perform aggressive force removal
if ($standardUninstallSucceeded) {
    $cleanupMode = "cleanup"
    $cleanupDescription = "Performing post-uninstall cleanup"
} else {
    $cleanupMode = "force uninstall"
    $cleanupDescription = "Performing force uninstall"
}

Write-LogMessage -Level Warning -Message "$cleanupDescription of any remaining SCCM components..."

# STEP 3: Remove SCCM Windows services
# - ccmexec: Main SCCM client service ("SMS Agent Host")
# - ccmsetup: SCCM client installation/maintenance service
Write-LogMessage -Level Info -Message "(Step 3 of 9) Stopping and removing CcmExec and CcmSetup services ($cleanupMode)."
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
}

# STEP 4: Terminate any remaining SCCM-related processes
# Searches for processes by name pattern (*ccm*) and by loaded modules
# This ensures no SCCM processes are holding files/registry keys that need cleanup
Write-LogMessage -Level Info -Message "(Step 4 of 9) Killing all tasks related to SCCM ($cleanupMode)."
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
}

# STEP 5: Remove SCCM files and directories
# Uses takeown to gain ownership of files before deletion (handles permission issues)
Write-LogMessage -Level Info -Message "(Step 5 of 9) Deleting all SCCM folders and files ($cleanupMode)."
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
}

# STEP 6: Remove SCCM registry keys
# This removes all traces of SCCM from the Windows registry
Write-LogMessage -Level Info -Message "(Step 6 of 9) Deleting all SCCM reg keys ($cleanupMode)."

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

# STEP 7: Remove SCCM WMI (Windows Management Instrumentation) namespaces
# These namespaces contain SCCM client configuration and status information
# Removing them ensures complete cleanup of SCCM client data structures
Write-LogMessage -Level Info -Message "(Step 7 of 9) Remove SCCM namespaces from WMI repo ($cleanupMode)."
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

# STEP 8: Final completion and error reporting
# Report overall success and any non-critical errors encountered
Write-LogMessage -Level Success -Message "$cleanupDescription completed successfully."

# Report any non-critical errors that occurred during execution
# These errors don't prevent the script from completing but should be reviewed
if ( $errorCount -gt 0 ){
    Write-LogMessage -Level Warning -Message "There were $errorCount non-critical errors."
}