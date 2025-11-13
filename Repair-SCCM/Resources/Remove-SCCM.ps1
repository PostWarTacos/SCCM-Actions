# ------------------- FUNCTIONS -------------------- #

function Get-UserInputWithTimeout {
    param(
        [string]$Prompt,
        [int]$TimeoutSeconds = 10,
        [string[]]$ValidValues = @()
    )
    
    Write-Host "$Prompt" -ForegroundColor Yellow
    Write-Host "Script will exit if no input provided within $TimeoutSeconds seconds" -ForegroundColor Red
    
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
            Write-Host "No input provided. Exiting script." -ForegroundColor Red
            exit 1
        }
        
        # Validate against allowed values if provided
        if ($ValidValues.Count -gt 0 -and $result.ToUpper().Trim() -notin $ValidValues) {
            Write-Host "Invalid input: $result" -ForegroundColor Red
            return $null  # Invalid input - allows retry
        }
        
        return $result.ToUpper().Trim()
    } else {
        Stop-Job $job
        Remove-Job $job
        Write-Host "Timeout reached. No input provided. Exiting script." -ForegroundColor Red
        exit 1
    }
}

function Stop-ServiceWithTimeout {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,

        [int]$TimeoutSeconds = 30
    )

    Write-Host "Attempting to stop service: $ServiceName" -ForegroundColor Yellow
    
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
            Write-Host "Service $ServiceName stopped successfully." -ForegroundColor Green
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
        Write-Host "Timeout reached! Forcefully terminating the service process." -ForegroundColor Green
        $serviceProcess = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq $ServiceName }
        if ( $serviceProcess -and $serviceProcess.ProcessId -ne 0 ) {
            Stop-Process -Id $serviceProcess.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "Service process terminated." -ForegroundColor Green
        } else {
            Write-Host "Service was already stopped or process not found." -ForegroundColor Yellow
        }
    }
}

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
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
    
    # Add to health log array for backward compatibility
    $healthLog.Add($logEntry) | Out-Null
}


# ------------------- VARIABLES -------------------- #

# Creates an Arraylist which is mutable and easier to manipulate than an array.
$healthLog = [System.Collections.ArrayList]@()

# Error handling
$errorCount = 0
# $critErrors = $false
$success = $false

# Directories
$healthLogPath = "C:\drivers\ccm\logs"

# ------------------- CREATE DIRECTORIES -------------------- #

# Check for directory for ccm logs used in this script
if ( -not ( Test-Path $healthLogPath )) {
    mkdir $healthLogPath | Out-Null
}

# ------------------- MAIN SCRIPT -------------------- #

Clear-Host

$message = "Attempting repair actions on $(hostname)"
Write-LogMessage -Level Info -Message $message

# Remove certs and restart service
# Possible this is the only needed fix.
# Run this first step and then test if it worked before 
Write-Host "(Step 1 of 9) Stopping CcmExec to remove SMS certs." -ForegroundColor Cyan
$found = Get-Service CcmExec -ErrorAction SilentlyContinue
if ( $found ){
    try {
        Stop-ServiceWithTimeout CcmExec
        write-host "Removing SMS certs."  -ForegroundColor Yellow
        Get-ChildItem Cert:\LocalMachine\SMS | Remove-Item
        Start-Service CcmExec -ErrorAction SilentlyContinue
    
        # Start service
        Start-Sleep -Seconds 10 # Allow some time for the service to start
    
        # Attempt to contact MP and pull new policy. If this works, client should be healthy.
        Invoke-CimMethod -Namespace "root\ccm" -ClassName "SMS_Client" -MethodName "TriggerSchedule" -Arguments @{sScheduleID="{00000000-0000-0000-0000-000000000021}"} | Out-Null
        $policyAgentLogs = "C:\Windows\CCM\Logs\PolicyAgent.log"
        $recentLogs = Get-Content $policyAgentLogs -Tail 50
        $patterns = @(
            "Updated namespace .* successfully",
            "Successfully received policy assignments from MP",
            "PolicyAgent successfully processed the policy assignment",
            "Completed policy evaluation cycle"
        )
                                 
        $success = $recentLogs | Select-String -Pattern $patterns
        
        # Announce success/fail
        if ( $success ) {
            $message = "Service restarted successfully and MP contacted. Assuming resolved, ending script."
            Write-LogMessage -Level Success -Message $message
            return 102
        } else {
            $message = "Failed to start service. Continuing with SCCM Client removal and reinstall."
            Write-LogMessage -Level Error -Message $message
        }   
    }
    catch {
           $message = "Failed to start service. Continuing with SCCM Client removal and reinstall."
            Write-LogMessage -Level Error -Message $message
    }
} Else {
    $message = "CcmExec Service not installed. Continuing with SCCM Client removal and reinstall."
    Write-LogMessage -Level Warning -Message $message
}

# Clean uninstall
Write-Host "(Step 2 of 9) Performing SCCM uninstall." -ForegroundColor Cyan
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
        $message = "Standard ccmsetup.exe uninstall completed successfully."
        Write-LogMessage -Level Success -Message $message
        $standardUninstallSucceeded = $true
    }
    catch {
        $message = "Standard uninstall failed: $_ - Proceeding with force cleanup."
        Write-LogMessage -Level Warning -Message $message
        $errorCount++
    }
} else {
    $message = "Ccmsetup.exe not found - Proceeding with force cleanup."
    Write-LogMessage -Level Warning -Message $message
}

# Determine cleanup mode messaging
if ($standardUninstallSucceeded) {
    $cleanupMode = "cleanup"
    $cleanupDescription = "Performing post-uninstall cleanup"
} else {
    $cleanupMode = "force uninstall"
    $cleanupDescription = "Performing force uninstall"
}

Write-Host "$cleanupDescription of any remaining SCCM components..." -ForegroundColor Yellow

# Remove both services "ccmsetup" and "SMS Agent Host"
Write-Host "(Step 3 of 9) Stopping and removing CcmExec and CcmSetup services ($cleanupMode)." -ForegroundColor Cyan
$services = @(
    "ccmexec",
    "ccmsetup"
)
foreach ( $service in $services ){
    if ( get-service $service -ErrorAction SilentlyContinue ){
        try {
            Stop-ServiceWithTimeout $service
            & sc.exe delete $service
            $message = "$service service found and removed."
            Write-LogMessage -Level Success -Message $message   
        }
        catch {
            $message = "Failed to stop and remove $service service. Continuing script but may cause issues."
            Write-LogMessage -Level Error -Message $message
            $errorCount++
        }
    } else{
        $message = "$service service not found."
        Write-LogMessage -Level Warning -Message $message
    }        
}

# Kill all SCCM client processes
Write-Host "(Step 4 of 9) Killing all tasks related to SCCM ($cleanupMode)." -ForegroundColor Cyan
$files = @(
    "C:\Windows\CCM",
    "C:\Windows\ccmcache",
    "C:\Windows\ccmsetup",
    "C:\Windows\SMSCFG.ini"
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
                $message = "$($proc.ProcessName) killed. Process was tied to $file."
                Write-LogMessage -Level Success -Message $message    
            }
            catch {
                $message = "Failed to kill $($proc.ProcessName) process. Continuing script but may cause issues."
                Write-LogMessage -Level Error -Message $message
                $errorCount++
            }
        } else{
            $message = "Could not find a process tied to $file."
            Write-LogMessage -Level Warning -Message $message
        }
    } catch {
        $message = "Error checking processes for $file. Continuing script."
        Write-LogMessage -Level Warning -Message $message
    }
}

# Delete the folders for SCCM
Write-Host "(Step 5 of 9) Deleting all SCCM folders and files ($cleanupMode)." -ForegroundColor Cyan
foreach ( $file in $files ){
    if ( Test-Path $file ){
        try {
            $null = takeown /F $file /R /A /D Y 2>&1
            $ConfirmPreference = 'None'
            Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue
            $message = "$file found and removed."
            Write-LogMessage -Level Success -Message $message    
        }
        catch {
            $message = "Failed to remove $file file(s). Continuing script but may cause issues."
            Write-LogMessage -Level Error -Message $message
            $errorCount++
        }
    } else{
        $message = "$file not found."
        Write-LogMessage -Level Warning -Message $message
    }
}

# Delete the main registry keys associated with SCCM
Write-Host "(Step 6 of 9) Deleting all SCCM reg keys ($cleanupMode)." -ForegroundColor Cyan
$keys= @(
    "HKLM:\Software\Microsoft\CCM",
    "HKLM:\Software\Microsoft\SMS",
    "HKLM:\Software\Microsoft\ccmsetup",
    "HKLM:\Software\Wow6432Node\Microsoft\CCM",
    "HKLM:\Software\Wow6432Node\Microsoft\SMS",
    "HKLM:\Software\Wow6432Node\Microsoft\ccmsetup",
    "HKLM:\System\CurrentControlSet\Services\CcmExec",
    "HKLM:\System\CurrentControlSet\Services\prepdrvr",
    "HKLM:\System\CurrentControlSet\Services\ccmsetup",
    "HKLM:\System\CurrentControlSet\Services\eventlog\Application\Configuration Manager Agent",
    "HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*"
)
foreach ( $key in $keys ){
    if( Test-Path $KEY ){
        try {
            Remove-Item $KEY -Recurse -Force -ErrorAction SilentlyContinue
            $message = "$KEY found and removed."
            Write-LogMessage -Level Success -Message $message
        }
        catch {
            $message = "Failed to remove $key reg key. Continuing script but may cause issues."
            Write-LogMessage -Level Error -Message $message
            $errorCount++
        }
    } Else { 
        $message = "Could not find $KEY."
        Write-LogMessage -Level Warning -Message $message
    }
}

# Remove SCCM namespaces from WMI repository
Write-Host "(Step 7 of 9) Remove SCCM namespaces from WMI repo ($cleanupMode)." -ForegroundColor Cyan
try {
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    $message = "Namespace(s) found and removed."
    Write-LogMessage -Level Success -Message $message
}
catch {
    $message = "Failed to remove namespace(s). Continuing script but may cause issues."
    Write-LogMessage -Level Error -Message $message
    $errorCount++
}

# Cleanup completion message
$message = "$cleanupDescription completed successfully."
Write-LogMessage -Level Success -Message $message

# Download required files before reboot
Write-Host "(Step 8 of 9) Downloading SCCM installation files." -ForegroundColor Cyan
try {
    # Determine domain and set appropriate source path using improved detection
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        if ( $domain -match "DDS" ) {
            $cpSource = "\\scanz223\SMS_DDS\Client" # DDS
        }
        elseif ( $domain -match "DPOS" ) {
            $cpSource = "\\slrcp223\SMS_PCI\Client" # PCI
        }
        else {
            # Unknown domain - prompt for input with timeout
            Write-Warning "Unknown domain detected: $domain"
            Write-Host "Unable to automatically determine SCCM source path." -ForegroundColor Yellow
            Write-Host "Known domains and their source paths:" -ForegroundColor Cyan
            Write-Host "  - DDS domains: \\scanz223\SMS_DDS\Client" -ForegroundColor White
            Write-Host "  - DPOS domains: \\slrcp223\SMS_PCI\Client" -ForegroundColor White
            
            do {
                $domainChoice = Get-UserInputWithTimeout -Prompt "Please enter the domain type (DDS, PCI, or DPOS)" -TimeoutSeconds 10 -ValidValues @("DDS", "PCI", "DPOS")
                
                if ($null -eq $domainChoice) {
                    Write-Host "Invalid choice. Please enter 'DDS', 'PCI', or 'DPOS'." -ForegroundColor Red
                    continue
                }
                
                break
            } while ($true)
            
            if ($domainChoice -eq "DDS") {
                $cpSource = "\\scanz223\SMS_DDS\Client"
            }
            elseif ($domainChoice -eq "PCI" -or $domainChoice -eq "DPOS") {
                $cpSource = "\\slrcp223\SMS_PCI\Client"
            }
            
            Write-Host "Using source path: $cpSource" -ForegroundColor Green
        }
    }
    catch {
        # Failed to get domain information - prompt for input
        Write-Error "Failed to get domain information: $_"
        Write-Host "Unable to automatically determine SCCM source path." -ForegroundColor Yellow
        Write-Host "Known domains and their source paths:" -ForegroundColor Cyan
        Write-Host "  - DDS domains: \\scanz223\SMS_DDS\Client" -ForegroundColor White
        Write-Host "  - DPOS domains: \\slrcp223\SMS_PCI\Client" -ForegroundColor White
        
        do {
            $domainChoice = Get-UserInputWithTimeout -Prompt "Please enter the domain type (DDS, PCI, or DPOS)" -TimeoutSeconds 10 -ValidValues @("DDS", "PCI", "DPOS")
            
            if ($null -eq $domainChoice) {
                Write-Host "Invalid choice. Please enter 'DDS', 'PCI', or 'DPOS'." -ForegroundColor Red
                continue
            }
            
            if ($domainChoice -eq "DDS") {
                $cpSource = "\\scanz223\SMS_DDS\Client"
                break
            }
            elseif ($domainChoice -eq "PCI" -or $domainChoice -eq "DPOS") {
                $cpSource = "\\slrcp223\SMS_PCI\Client"
                break
            }
        } while ($true)
        
        Write-Host "Using source path: $cpSource" -ForegroundColor Green
    }

    # Set destination path
    $cpDestination = "C:\drivers\ccm\ccmsetup"
    
    # Ensure destination directory exists
    if ( -not ( Test-Path $cpDestination )) {
        New-Item -ItemType Directory -Path $cpDestination -Force | Out-Null
    }

    # Download files using robocopy
    $message = "Copying SCCM installation files from $cpSource to $cpDestination"
    Write-LogMessage -Level Info -Message $message
    
    try {
        Copy-Item $cpSource $cpDestination -Force -Recurse -ErrorAction Stop
        Write-LogMessage -Level Success -Message "SCCM installation files copied successfully."
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to copy SCCM installation files. Error: $_"
        $errorCount++
    }

    # Verify ccmsetup.exe exists
    $ccmSetupPath = Join-Path $cpDestination "ccmsetup.exe"
    if ( Test-Path $ccmSetupPath ) {
        $message = "Verified ccmsetup.exe exists at $ccmSetupPath"
        Write-LogMessage -Level Success -Message $message
    }
    else {
        throw "ccmsetup.exe not found after download at $ccmSetupPath"
    }
}
catch {
    $message = "Failed to download SCCM installation files. Error: $_"
    Write-LogMessage -Level Error -Message $message
    $errorCount++
}

# Add RunOnce registry key to trigger Reinstall-SCCMTask after reboot
Write-Host "(Step 9 of 9) Adding RunOnce registry key to trigger Reinstall-SCCMTask after reboot." -ForegroundColor Cyan
try {
    $runOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $taskCommand = "schtasks.exe /run /tn `"Reinstall-SCCMTask`""

    # Create the RunOnce registry entry
    Set-ItemProperty -Path $runOnceKey -Name "TriggerReinstallSCCMTask" -Value $taskCommand -Force

    $message = "RunOnce registry key created successfully. Reinstall-SCCMTask will be triggered after reboot."
    Write-LogMessage -Level Success -Message $message
}
catch {
    $message = "Failed to create RunOnce registry key. Error: $_"
    Write-LogMessage -Level Error -Message $message
    $errorCount++
}

Write-Host "Uninstall and wipe of SCCM completed." -ForegroundColor Green

if ( $errorCount -gt 0 ){
    Write-Host "There were $errorCount non-critical errors." -ForegroundColor Yellow
}

# Reboot the machine to trigger the RunOnce task
Write-Host "Rebooting machine to trigger Repair-SCCMTask..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Restart-Computer -Force