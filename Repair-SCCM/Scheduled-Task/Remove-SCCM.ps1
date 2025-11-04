# ------------------- FUNCTIONS -------------------- #

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

function Update-HealthLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [switch]$WriteHost,

        [Parameter()]
        [string]$Color,

        [Parameter()]
        [switch]$Return
    )

    $healthLog.Add("[$(Get-Date -Format 'dd-MMM-yy HH:mm:ss')] Message: $message") | Out-Null

    if ( $PSBoundParameters.ContainsKey('WriteHost') -and $PSBoundParameters.ContainsKey('Color') ) {
        Write-Host $message -ForegroundColor $Color
    }
    else {
        Write-Host $Message
    }

    if ($PSBoundParameters.ContainsKey('Return')) {
        $null = return $message | Out-Null
    }
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
Update-HealthLog -path $healthLogPath -Message $message -WriteHost -Color Cyan

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
        Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000021}" | Out-Null
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
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
            return 102
        } else {
            $message = "Failed to start service. Continuing with SCCM Client removal and reinstall."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
        }   
    }
    catch {
           $message = "Failed to start service. Continuing with SCCM Client removal and reinstall."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
    }
} Else {
    $message = "CcmExec Service not installed. Continuing with SCCM Client removal and reinstall."
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
}

# Clean uninstall
Write-Host "(Step 2 of 9) Performing SCCM uninstall." -ForegroundColor Cyan
if ( Test-Path C:\Windows\ccmsetup\ccmsetup.exe ){
    try {
        Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force
        Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force
        $proc = Start-Process -FilePath "C:\Windows\ccmsetup\ccmsetup.exe" -ArgumentList "/uninstall" -PassThru -Verbose
        $proc.WaitForExit()
        if ( $proc.ExitCode -ne 0 ){
            throw "SCCM uninstall failed with exit code $($proc.exitcode)"
        }
        $message = "Ccmsetup.exe uninstalled."
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
    }
    catch {
        $message = "Failed to uninstall ccm. Ending script. Caught error: $_"
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
        return $_
    }
} else {
    $message = "Ccmsetup.exe not found."
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
}

# Remove both services “ccmsetup” and “SMS Agent Host”
Write-Host "(Step 3 of 9) Stopping and removing CcmExec and CcmSetup services." -ForegroundColor Cyan
$services = @(
    "ccmexec",
    "ccmsetup"
)
foreach ( $service in $services ){
    if ( get-service $service -ErrorAction SilentlyContinue ){
        try {
            Stop-ServiceWithTimeout $service
            sc delete $service -Force -ErrorAction SilentlyContinue
            $message = "$service service found and removed."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green   
        }
        catch {
            $message = "Failed to stop and remove $service service. Continuing script but may cause issues."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
            $errorCount++
        }
    } else{
        $message = "$service service not found."
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
    }        
}

# Kill all SCCM client processes
Write-Host "(Step 4 of 9) Killing all tasks related to SCCM." -ForegroundColor Cyan
$files = @(
    "C:\Windows\CCM",
    "C:\Windows\ccmcache",
    "C:\Windows\ccmsetup",
    "C:\Windows\SMSCFG.ini"
)
foreach ( $file in $files ){
    $proc = Get-Process | Where-Object { $_.modules.filename -like "$file*" }
    if ($proc){
        try {
            Stop-Process $proc.Id -Force -ErrorAction SilentlyContinue
            $message = "$($proc.name) killed. Process was tied to $file."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green    
        }
        catch {
            $message = "Failed to kill $proc process. Continuing script but may cause issues."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
            $errorCount++
        }
    } Else{
        $message = "Could not find a process tied to $file."
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
    }
}

# Delete the folders for SCCM
Write-Host "(Step 5 of 9) Deleting all SCCM folders and files." -ForegroundColor Cyan
foreach ( $file in $files ){
    if ( Test-Path $file ){
        try {
            $null = takeown /F $file /R /A /D Y 2>&1
            $ConfirmPreference = 'None'
            Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue
            $message = "$file found and removed."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green    
        }
        catch {
            $message = "Failed to remove $file file(s). Continuing script but may cause issues."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
            $errorCount++
        }
    } else{
        $message = "$file not found."
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
    }
}

# Delete the main registry keys associated with SCCM
Write-Host "(Step 6 of 9) Deletinag all SCCM reg keys." -ForegroundColor Cyan
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
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
        }
        catch {
            $message = "Failed to remove $key reg key. Continuing script but may cause issues."
            Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
            $errorCount++
        }
    } Else { 
        $message = "Could not find $KEY."
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
    }
}

# Remove SCCM namespaces from WMI repository
Write-Host "(Step 7 of 9) Remove SCCM namespaces from WMI repo." -ForegroundColor Cyan
try {
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
    $message = "Namespace(s) found and removed."
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
}
catch {
    $message = "Failed to remove namespace(s). Continuing script but may cause issues."
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red -return
    $errorCount++
}

# Download required files before reboot
Write-Host "(Step 8 of 9) Downloading SCCM installation files." -ForegroundColor Cyan
try {
    # Determine domain and set appropriate source path
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    if ( $domain -match "DDS" ) {
        $cpSource = "\\scanz223\SMS_DDS\Client" # DDS
    }
    elseif ( $domain -match "DPOS" ) {
        $cpSource = "\\slrcp223\SMS_PCI\Client" # PCI
    }
    else {
        throw "Unknown domain detected. Cannot determine SCCM source path."
    }

    # Set destination path
    $cpDestination = "C:\drivers\ccm\ccmsetup"
    
    # Ensure destination directory exists
    if ( -not ( Test-Path $cpDestination )) {
        New-Item -ItemType Directory -Path $cpDestination -Force | Out-Null
    }

    # Download files using robocopy
    $message = "Copying SCCM installation files from $cpSource to $cpDestination"
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Yellow
    
    $robocopyResult = & robocopy $cpSource $cpDestination /E /Z /MT:4 /R:1 /W:2 /NP /V
    $robocopyExitCode = $LASTEXITCODE
    
    # Robocopy exit codes 0-7 are considered success
    if ( $robocopyExitCode -le 7 ) {
        $message = "SCCM installation files downloaded successfully."
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
    }
    else {
        throw "Robocopy failed with exit code: $robocopyExitCode"
    }

    # Verify ccmsetup.exe exists
    $ccmSetupPath = Join-Path $cpDestination "ccmsetup.exe"
    if ( Test-Path $ccmSetupPath ) {
        $message = "Verified ccmsetup.exe exists at $ccmSetupPath"
        Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
    }
    else {
        throw "ccmsetup.exe not found after download at $ccmSetupPath"
    }
}
catch {
    $message = "Failed to download SCCM installation files. Error: $_"
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red
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
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Green
}
catch {
    $message = "Failed to create RunOnce registry key. Error: $_"
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red
    $errorCount++
}

Write-Host "Uninstall and wipe of SCCM completed." -ForegroundColor Green

$healthLog >> $healthLogPath\HealthCheck.txt

if ( $errorCount -gt 0 ){
    Write-Host "There were $errorCount non-critical errors." -ForegroundColor Yellow
}

# Reboot the machine to trigger the RunOnce task
Write-Host "Rebooting machine to trigger Repair-SCCMTask..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Restart-Computer -Force