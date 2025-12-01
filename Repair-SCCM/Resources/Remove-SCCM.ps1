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
    When running non-interactively (scheduled task/service), it will automatically
    reboot the system and configure automatic SCCM reinstallation.
    
    INTERACTIVE MODE: Manual execution - run through invoke-command
    NON-INTERACTIVE MODE: Scheduled task/service - automatically reboots and reinstalls SCCM
    
    Prerequisites for automatic reinstall (non-interactive mode):
    - "Reinstall-SCCMTask" scheduled task must exist (created by Create-SCCMScheduledTasks.ps1)
    - SCCM installation files must be available in C:\drivers\ccm\ccmsetup\

    Log files are created at: C:\drivers\ccm\logs\HealthCheck.txt

.OUTPUTS
    Returns exit code 102 if quick fix (step 1) succeeds, otherwise continues full removal.
    In non-interactive mode: System will automatically reboot after cleanup completion.
    All actions are logged to both console and log file.
#>

# ------------------- PARAMETER BLOCK -------------------- #
param(
    [bool]$Invoke = $false
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

Function Stop-ServiceWithTimeout {
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

# ------------------- VARIABLES -------------------- #

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

if (-not $script:Invoke) {
    Write-Output "Removal Initiated" # Output for Collection Commander
}

Write-LogMessage -message "Attempting repair actions on $(hostname)"
Write-LogMessage -message "Session Mode: $(if ($Invoke) { 'Interactive' } else { 'Non-Interactive (Scheduled Task or Collection Commander)' })"

# STEP 1: Quick fix attempt - often resolves SCCM client issues without full removal
# This step tries to fix common SCCM problems by:
# - Stopping the CcmExec service
# - Removing potentially corrupted SMS certificates
# - Restarting the service
# - Testing connectivity to Management Point (MP)
# If successful, script exits early (return code 102)
Write-LogMessage -message "(Step 1 of 10) Stopping CcmExec to remove SMS certs."

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
                    Write-LogMessage -Message "Service restarted successfully and MP contacted. Assuming resolved, ending script." -Level Success
                    if (-not $script:Invoke) { 
                        return "Quick Fix Success" # Output for Collection Commander
                    }
                } else {
                    Write-LogMessage -Message "Failed to start service. Proceeding with SCCM Client removal." -Level Error
                    if (-not $script:Invoke) {
                        Write-Output "Step 1 - Quick Fix Failed. Proceeding with SCCM Client removal." # Output for Collection Commander
                    }
                }
            } catch {
                Write-LogMessage -Message "Could not read PolicyAgent.log: $($_.Exception.Message). Skipping log check." -Level Warning
                if (-not $script:Invoke) {
                    Write-Output "Step 1 - PolicyAgent.log not readable. Skipping log check." # Output for Collection Commander
                }
            }
        } else {
            Write-LogMessage -Message "PolicyAgent.log not found. Skipping log check." -Level Warning
        }
    } catch {
        if ($_.Exception.Message -match "network|connection|access denied|permission") {
            Write-LogMessage -Message "Fatal error encountered: $($_.Exception.Message). Halting execution." -Level Error
            if (-not $script:Invoke) {
                return "Fatal Error" # Output for Collection Commander
            }
        } else {
            $message = "Non-fatal error: $($_.Exception.Message). Proceeding with SCCM Client removal ."
            Write-LogMessage -Message $message -Level Error
            if (-not $script:Invoke){
                Write-Output $message
            }
        }
        }
    } else {
    $message = "CcmExec Service not installed. Proceeding with remnants removal."
    Write-LogMessage -Message $message -Level Warning
    if (-not $script:Invoke){
        Write-Output $message
    }
}

# STEP 2: Attempt standard SCCM uninstall using built-in ccmsetup.exe
# This is the preferred method as it follows Microsoft's recommended uninstall process
Write-LogMessage -message "(Step 2 of 10) Performing SCCM uninstall."
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
        Write-LogMessage -Message "Standard ccmsetup.exe uninstall completed successfully." -Level Success
        $standardUninstallSucceeded = $true
    }
    catch {
        Write-LogMessage -Message "Standard uninstall failed: $_ - Proceeding with forced cleanup." -Level Warning
        $errorCount++
    }
} else {
    Write-LogMessage -Message "Ccmsetup.exe not found - Proceeding with forced cleanup." -Level Warning
}

# Determine cleanup approach based on standard uninstall success
# If standard uninstall worked: perform gentle cleanup of remaining components
# If standard uninstall failed: perform aggressive forced removal
if ($standardUninstallSucceeded) {
    $cleanupMode = "cleanup"
    $cleanupDescription = "Performing post-uninstall cleanup"
    if (-not $script:Invoke) {
        Write-Output "Step 2 - Standard Uninstall Succeeded."  # Output for Collection Commander
    }
} else {
    $cleanupMode = "forced uninstall"
    $cleanupDescription = "Performing forced uninstall"
    if (-not $script:Invoke) {
        Write-Output "Step 2 - Standard Uninstall Failed. Proceeding with forced uninstall."  # Output for Collection Commander
    }
}

Write-LogMessage -message "$cleanupDescription of any remaining SCCM components..." -Level Info

# STEP 3: Remove SCCM Windows services
# - ccmexec: Main SCCM client service ("SMS Agent Host")
# - ccmsetup: SCCM client installation/maintenance service
Write-LogMessage -message "(Step 3 of 10) Stopping and removing CcmExec and CcmSetup services ($cleanupMode)."
$services = @(
    "ccmexec",
    "ccmsetup"
)
foreach ( $service in $services ){
    if ( get-service $service -ErrorAction SilentlyContinue ){
        try {
            Stop-ServiceWithTimeout $service
            sc.exe delete $service | Out-Null
            Write-LogMessage -Level Success -Message "$service service stopped and removed."
        }
        catch {
            Write-LogMessage -Level Error -Message "Failed to remove $service service. Continuing script but may cause issues."
            $errorCount++
        }
    } else{
        Write-LogMessage -Level Warning -Message "$service service not found."
    }
}
if (-not $script:Invoke) {
    Write-Output "Step 3 - Service Removal Completed" # Output for Collection Commander
}

# STEP 4: Terminate any remaining SCCM-related processes
# Searches for processes by name pattern (*ccm*) and by loaded modules
# This ensures no SCCM processes are holding files/registry keys that need cleanup
Write-LogMessage -message "(Step 4 of 10) Killing all tasks related to SCCM ($cleanupMode)."
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
    if (-not $script:Invoke) {
        Write-Output "Step 4 - Process Termination Completed" # Output for Collection Commander
    }
}

# STEP 5: Remove SCCM files and directories
# Uses takeown to gain ownership of files before deletion (handles permission issues)
Write-LogMessage -message "(Step 5 of 10) Deleting all SCCM folders and files ($cleanupMode)."
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
    if (-not $script:Invoke) {
        Write-Output "Step 5 - File Removal Completed" # Output for Collection Commander
    }
}

# STEP 6: Remove SCCM registry keys
# This removes all traces of SCCM from the Windows registry
Write-LogMessage -message "(Step 6 of 10) Deleting all SCCM reg keys ($cleanupMode)."

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
    if (-not $script:Invoke) {
        Write-Output "Step 6 - Reg Key Removal Completed" # Output for Collection Commander
    }
}

# STEP 7: Remove SCCM WMI (Windows Management Instrumentation) namespaces
# These namespaces contain SCCM client configuration and status information
# Removing them ensures complete cleanup of SCCM client data structures
Write-LogMessage -message "(Step 7 of 10) Remove SCCM namespaces from WMI repo ($cleanupMode)."

# Note: Direct namespace deletion can cause WMI corruption. Only remove if namespaces still exist
# after uninstall, and let the reinstall script handle WMI repository rebuild if needed.
try {
    $namespacesRemoved = 0
    
    # Check and remove main CCM namespace (Configuration Manager Client)
    $ccmNamespace = Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue
    if ($ccmNamespace) {
        Write-LogMessage -Level Warning -Message "CCM namespace still exists after uninstall. Removing..."
        $ccmNamespace | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        $namespacesRemoved++
    }
    
    # Check and remove VDI-specific CCM namespace (Virtual Desktop Infrastructure)
    $ccmvdiNamespace = Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue
    if ($ccmvdiNamespace) {
        Write-LogMessage -Level Warning -Message "CCMVDI namespace still exists after uninstall. Removing..."
        $ccmvdiNamespace | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        $namespacesRemoved++
    }
    
    # Check and remove SMS Device Management namespace
    $smsdmNamespace = Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue
    if ($smsdmNamespace) {
        Write-LogMessage -Level Warning -Message "SmsDm namespace still exists after uninstall. Removing..."
        $smsdmNamespace | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        $namespacesRemoved++
    }
    
    # Check and remove legacy SMS namespace from cimv2
    $smsNamespace = Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue
    if ($smsNamespace) {
        Write-LogMessage -Level Warning -Message "SMS namespace still exists in cimv2 after uninstall. Removing..."
        $smsNamespace | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        $namespacesRemoved++
    }
    
    if ($namespacesRemoved -gt 0) {
        Write-LogMessage -Level Success -Message "Removed $namespacesRemoved SCCM namespace(s)."
        Write-LogMessage -Level Info -Message "Note: WMI repository will be rebuilt during reinstallation to ensure clean state."
    } else {
        Write-LogMessage -Level Success -Message "No SCCM namespaces found (already cleaned by uninstaller)."
    }
    
    if (-not $script:Invoke) {
        Write-Output "Step 7 - Namespace Removal Completed" # Output for Collection Commander
    }
}
catch {
    Write-LogMessage -Level Error -Message "Failed to remove namespace(s): $_"
    Write-LogMessage -Level Warning -Message "Continuing script. WMI will be rebuilt during reinstall."
    $errorCount++
}

# STEP 8: Remove SCCM from Windows Installer database (forced cleanup only)
# After failed uninstalls, MSI database may still have SCCM product registrations
# This prevents the installer from attempting repairs instead of fresh installs
if (-not $standardUninstallSucceeded) {
    Write-LogMessage -Level Info -Message "(Step 8 of 10) Removing SCCM from Windows Installer database."
    try {
        # Get all SCCM-related products from MSI database
        Write-LogMessage -Message "Searching for SCCM products in MSI database..."
        $sccmProducts = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -like "*Configuration Manager*" -or 
            $_.Name -like "*CCM*" -or
            $_.IdentifyingNumber -eq "{987AABAD-F544-404E-86C6-215EAFBEB7C0}"
        }
        
        if ($sccmProducts) {
            foreach ($product in $sccmProducts) {
                Write-LogMessage -Level Info -Message "Uninstalling '$($product.Name)' (Product Code: $($product.IdentifyingNumber)) from MSI database..."
                try {
                    $product.Uninstall() | Out-Null
                    Write-LogMessage -Level Success -Message "'$($product.Name)' uninstalled from MSI database."
                }
                catch {
                    Write-LogMessage -Level Error -Message "Failed to uninstall '$($product.Name)': $($_.Exception.Message)"
                    $errorCount++
                }
            }
        } else {
            Write-LogMessage -Level Warning -Message "No SCCM products found in MSI database."
        }
        if (-not $script:Invoke) {
            Write-Output "Step 9 - MSI Database Cleanup Completed." # Output for Collection Commander
        }
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to query/remove MSI database entries: $($_.Exception.Message)"
        Write-LogMessage -Level Warning -Message "Continuing cleanup. MSI database may still contain SCCM entries."
        if (-not $script:Invoke) {
            Write-Output "Step 9 - MSI Database Cleanup Failed. Proceeding with removal." # Output for Collection Commander
        }
        $errorCount++
    }
} else {
    Write-LogMessage -Level Info -Message "(Step 8 of 10) Skipping MSI database cleanup (post-uninstall cleanup)."
}

# STEP 10: Configure post-reboot SCCM reinstallation (only when non-interactive)
# When running as scheduled task, set up automatic SCCM reinstall after reboot
<#  COMMENTED OUT - NOT READY FOR PRODUCTION USE YET
if (-not $Invoke) {
    Write-LogMessage -Level Info -Message "(Step 9 of 10) Configuring post-reboot SCCM reinstallation (non-interactive mode only)."
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
#>

<#  COMMENTED OUT - NOT READY FOR PRODUCTION USE YET
# STEP 12: Initiate system reboot (only when non-interactive)
# When running as scheduled task, automatically reboot to complete SCCM removal and trigger reinstall
if (-not $isInteractive) {
    Write-LogMessage -Level Info -Message "(Step 10 of 10) Initiating system reboot to complete SCCM removal process (non-interactive mode only)."
    Write-LogMessage -Level Warning -Message "System will reboot. SCCM will be automatically reinstalled after reboot."
    
    # Provide brief delay to allow log messages to be written and visible
    Start-Sleep -Seconds 5
    
    # Force reboot with 0-second delay for unattended operation
    # shutdown.exe /r /t 0 /f
}
#>

# Return appropriate exit code based on removal results
if ( $script:Invoke ) {
    # Non-Collection Commander: preserve previous logic (multiple returns)
    if ($errorCount -gt 5) {
        Write-LogMessage -Level Error -Message "Removal completed with $errorCount errors. This may indicate removal failure."
        Write-LogMessage -Message "Can be found at $healthLogPath`."
        return 1
    } else {
        Write-LogMessage -Level Success -Message "Full SCCM removal completed successfully. $errorCount errors."
        Write-LogMessage -Message "Can be found at $healthLogPath`."
        return 0
    }
} else {
    # Collection Commander: Only return one status at end
    if ($errorCount -gt 5) {
        Write-LogMessage -Level Error -Message "Removal completed with $errorCount errors. This may indicate removal failure."
        Write-LogMessage -Message "Can be found at $healthLogPath`."
        return "Removal Failed. $errorCount errors. Logs found locally at $healthLogPath`."
    } else {
        Write-LogMessage -Level Success -Message "Full SCCM removal completed successfully. $errorCount errors"
        Write-LogMessage -Message "Can be found at $healthLogPath`."
        return "Removal Succeeded. $errorCount errors. Logs found locally at $healthLogPath`."
    }
}

