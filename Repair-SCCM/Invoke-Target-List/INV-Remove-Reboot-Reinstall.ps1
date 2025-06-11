# This script removes the SCCM client, reboots the machine, and reinstalls the client.
# It logs status updates using Update-HealthLog.

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

# -------------------- VARIABLES -------------------- #

# URLs on local machine
$desktop = [Environment]::GetFolderPath('Desktop')
$remediationSuccess = join-path $desktop "success.txt"
$remediationFail = join-path $desktop "fail.txt"

# Get targets
$targetFile = Get-FileName -initialDirectory $desktop
$targets = Get-Content $targetFile

# File Check
$targetPath = "C:\drivers\ccm\ccmsetup"
$exeOnSrvr = Join-Path $cpSource "ccmsetup.exe"
[version]$correctVersion = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($exeOnSrvr)).FileVersion # get ver of installer on server

# URLs for copying exe to machine
# cpDestination is assigned per machine in the File Check section
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
if ( $domain -match "DDS" ) {
    $cpSource = "\\scanz223\SMS_DDS\Client" # DDS
}
elseif ( $domain -match "DPOS" ) {
    $cpSource = "\\slrcp223\SMS_PCI\Client" # PCI
}

# Directories
$healthLogPath = "C:\drivers\ccm\logs"

# ------------------------------------------------------------
# Start of For loop
# ------------------------------------------------------------

foreach ( $t in $targets ){

    Write-Host "Starting SCCM remediation on $t" -ForegroundColor Green
    
    Write-Host "Testing network connection to $t"
    $failedToConnect = if ( -not ( Test-Connection $t -Count 2 -Quiet )){
        Write-host "Unable to connect to $t. Skipping it."
        Write-Output $t
        continue
    }

    pause
    Clear-Host

    # Reset variables to ensure correct results
    $removalResult = $null
    $installResult = $null

    # ------------------------------------------------------------
    # Start of Uninstall and Remove invoke-command
    # ------------------------------------------------------------

    $removalResult = invoke-command -ComputerName $t -ArgumentList $healthLogPath {
        param($healthLogPath_pass)

        # Define scoped log array
        $healthLog = [System.Collections.ArrayList]@()

        # -------------------- IN SCOPE FUNCTIONS -------------------- #

        function Stop-ServiceWithTimeout {
            [CmdletBinding()]
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

        # -------------------- IN SCOPE VARIABLES -------------------- #

        # Error handling
        # $critErrors = $false
        $errorCount = 0
        $success = $false

        # ------------------- CREATE DIRECTORIES -------------------- #

        # Check for directory for ccm logs used in this script
        if ( -not ( Test-Path $healthLogPath_pass )) {
            mkdir $healthLogPath_pass | Out-Null
        }

        # -------------------- UNINSTALL AND REMOVE -------------------- #

        $message = "Attempting repair actions on $(hostname)"
        Update-HealthLog -path $healthLogPath_pass -Message $message -WriteHost -Color Cyan

        # Clean uninstall
        Write-Host "(Step 1 of 11) Performing SCCM uninstall." -ForegroundColor Cyan
            if ( Test-Path C:\Windows\ccmsetup\ccmsetup.exe ){
                try {
                    Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force
                    Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force

                    # Start ccmsetup uninstall process in silent mode and wait for it to finish.
                    $proc = Start-Process -FilePath "C:\Windows\ccmsetup\ccmsetup.exe" -ArgumentList "/uninstall" -PassThru -Verbose
                    $proc.WaitForExit()

                    # Check uninstall result. If exit code is non-zero, log failure and exit.
                    if ( $proc.ExitCode -ne 0 ){
                        throw "SCCM uninstall failed with exit code $($proc.exitcode)"
                    }
                    $message = "Ccmsetup.exe uninstalled."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Green
                }
                catch {
                    $message = "Failed to uninstall ccm. Ending script. Caught error: $_"
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
                    return $false
                }
            }
            else {
                $message = "Ccmsetup.exe not found."
                Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Yellow
            }
        
        # Remove both services ccmexec and ccmsetup
        Write-Host "(Step 2 of 11) Stopping and removing CcmExec and CcmSetup services." -ForegroundColor Cyan
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
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Green   
                }
                catch {
                    $message = "Failed to stop and remove $service service. Continuing script but may cause issues."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
                    $errorCount++
                }
            } else{
                $message = "$service service not found."
                Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Yellow
            }        
        }

        # Kill all SCCM client processes
        Write-Host "(Step 3 of 11) Killing all tasks related to SCCM." -ForegroundColor Cyan
        $files = @(
            "C:\Windows\CCM",
            "C:\Windows\ccmcache",
            "C:\Windows\ccmsetup",
            "C:\Windows\SMSCFG.ini"
        )
        foreach ( $file in $files ){
            # Searches for processes that are using files located in the above dirs
            $proc = Get-Process | Where-Object { $_.modules.filename -like "$file*" }
            if ($proc){
                try {
                    Stop-Process $proc.Id -Force -ErrorAction SilentlyContinue
                    $message = "$($proc.name) killed. Process was tied to $file."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Green    
                }
                catch {
                    $message = "Failed to kill $proc process. Continuing script but may cause issues."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
                    $errorCount++
                }
            } Else{
                $message = "Could not find a process tied to $file."
                Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Yellow
            }
        }

        # Delete the folders for SCCM
        Write-Host "(Step 4 of 11) Deleting all SCCM folders and files." -ForegroundColor Cyan
        foreach ( $file in $files ){
            if ( Test-Path $file ){
                try {
                    $null = takeown /F $file /R /A /D Y 2>&1
                    $ConfirmPreference = 'None'
                    Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue
                    $message = "$file found and removed."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Green    
                }
                catch {
                    $message = "Failed to remove $file file(s). Continuing script but may cause issues."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
                    $errorCount++
                }
            } else{
                $message = "$file not found."
                Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Yellow
            }
        }

        # Delete the main registry keys associated with SCCM
        Write-Host "(Step 5 of 11) Deleting all SCCM reg keys." -ForegroundColor Cyan
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
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Green
                }
                catch {
                    $message = "Failed to remove $key reg key. Continuing script but may cause issues."
                    Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
                    $errorCount++
                }
            } Else { 
                $message = "Could not find $KEY."
                Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Yellow
            }
        }

        # Remove SCCM namespaces from WMI repository
        Write-Host "(Step 6 of 11) Remove SCCM namespaces from WMI repo." -ForegroundColor Cyan
        try {
            Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
            Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
            Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
            Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
            $message = "Namespace(s) found and removed."
            Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Green
        }
        catch {
            $message = "Failed to remove namespace(s). Continuing script but may cause issues."
            Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
            $errorCount++
        }

        if ( $errorCount -gt 0 ){
            $continue = Read-Host "There were $errorCount non-critical errors. Do you wish to continue with the reinstall? There's no guarantee it will succeed. (y/n)"
            if( $continue -eq "y" ){
                # Do nothing
            }
            elseif( $continue -eq "n" ){
                $endAfterLog = $true
            }
        }

        Write-Host "Uninstall and wipe of SCCM completed." -ForegroundColor Green

        # Write log to file
        $logFile = Join-Path $healthLogPath_pass "HealthCheck.txt"
        $healthLog | Out-File -Append -FilePath $logFile -Encoding UTF8
        if ( $endAfterLog ){ return $false }
    } 

    # ------------------------------------------------------------
    # End of Uninstall and Remove invoke-command
    # ------------------------------------------------------------

    if ( $removalResult -eq $false ){
        continue
    }

    # -------------------- FILE CHECK -------------------- #
    Write-Host "(Step 7 of 11) Verifying valid installer exe on machine." -ForegroundColor Cyan

    # ----------------------------------------
    # Start of File Check invoke-command
    # ----------------------------------------

    $fileCheck = Invoke-Command $t -ArgumentList $targetPath, $correctVersion {
        param($targetPath_pass, [version]$correctVersion_pass)
        $valid = $false

        # -------------------- IN SCOPE FUNCTIONS -------------------- #

        function Move-CCM {
            [cmdletbinding()]
            param(
                [parameter(Mandatory)]
                [string]$Source,

                [parameter(Mandatory)]
                [string]$Destination
            )

            $proc = Get-Process | Where-Object { $_.modules.filename -like "$source*" }
            Stop-Process $proc.Id -Force -ErrorAction SilentlyContinue
            Move-Item -Path $Source -Destination $Destination -Force
        }

        # Various locations the ccmsetup.exe can be found. Actions to move it to 1 dedicated location.
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

        # Checks each location above, verifies version number, and then performs the action if needed 
        foreach ( $entry in $locations ) {
            $exePath = Join-Path $entry.Path "ccmsetup.exe"

            if ( Test-Path $exePath ) {
                # test version of installer (NOT the currently installed version) exe on target machine
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
            Write-Warning "No valid ccmsetup.exe found."
            # write-host "Rebooting computer to complete uninstall."
            # restart-computer -force
        }
    }

    # ----------------------------------------
    # End of File Check invoke-command
    # ----------------------------------------

    # Copies files from server if needed  
    if ( $fileCheck -eq "Not Found" ){
        write-host "Copying files from server."    
        
        $cpDestination = "\\$t\C$\drivers\ccm\ccmsetup"
        
        # robocopy $cpSource $cpDestination /E /Z /MT:4 /R:2 /W:5 /NP /NFL /NDL /NJH /NJS
        robocopy $cpSource $cpDestination /E /Z /MT:4 /R:1 /W:2 /NP /V
        
        write-host "Copy complete."
    }

    # -------------------- REBOOT AND WAIT -------------------- #

    Write-Host "(Step 8 of 11) Rebooting." -ForegroundColor Cyan

    $initialBootTime = invoke-command -ComputerName $t { 
        ( Get-CimInstance -ComputerName $t -ClassName Win32_OperatingSystem ).LastBootUpTime
    }
    Write-Host "Rebooting $t" -ForegroundColor Cyan
    restart-computer -Force -ComputerName $t

    do {
        Start-Sleep -Seconds 60
        try {
            $currentBootTime = ( Get-CimInstance -ComputerName $t -ClassName Win32_OperatingSystem -ErrorAction Stop ).LastBootUpTime
        }
        catch {
            $currentBootTime = $initialBootTime
        }
    } while ( $currentBootTime -le $initialBootTime )

    # Delay to wait for computer to boot
    Start-Sleep -Seconds 120

    # -------------------- REINSTALL -------------------- #

    # ----------------------------------------
    # Start of Reinstall invoke-command
    # ----------------------------------------

    $installResult = Invoke-Command -computername $t -ArgumentList $healthLogPath, $correctVersion {
        param($healthLogPath_pass, [version]$correctVersion_pass)

        # Define scoped log array
        $healthLog = [System.Collections.ArrayList]@()

        # -------------------- IN SCOPE FUNCTIONS -------------------- #

        function Get-SiteCode{
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            if ( $domain -match "DDS" ) {
                $code = "DDS"
            }
            elseif ( $domain -match "DPOS" ) {
                $code = "PCI"
            }
            return $code
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

        function Start-HealthCheck {

            $allPassed = $true

            # Check if SCCM Client is installed
            if ( Test-Path "C:\Windows\CCM\CcmExec.exe" ) {
                Update-HealthLog -path $healthLogPath_pass -message "Found CcmExec.exe. SCCM installed." -WriteHost -color Green
            } else {
                Update-HealthLog -path $healthLogPath_pass -message "Cannot find CcmExec.exe." -WriteHost -color Red
                $allPassed = $false
            }

            # Check if SCCM Client Service is running
            $service = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
            if ( $service.Status -eq 'Running' ) {
                Update-HealthLog -path $healthLogPath_pass -message "Found CcmExec service and it is running." -WriteHost -color Green
            } elseif ( $service.Status -ne 'Running' ) {
                Update-HealthLog -path $healthLogPath_pass -message "Found CcmExec service but it is NOT running." -WriteHost -color Red
                $allPassed = $false
            } else {
                Update-HealthLog -path $healthLogPath_pass -message "CcmExec service could not be found." -WriteHost -color Red
                $allPassed = $false
            }

            # Check Client Version
            [version]$smsClientVer = (Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue).ClientVersion
            if ( $smsClientVer -ge $correctVersion_pass ) {
                Update-HealthLog -path $healthLogPath_pass -message "SCCM Client Version: $($smsClient.ClientVersion)" -WriteHost -color Green
            } else {
                Update-HealthLog -path $healthLogPath_pass -message "Client Version not found." -WriteHost -color Red
                $allPassed = $false
            }

            # Check Management Point Site Name
            $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction SilentlyContinue
            if ( $mp.Name ) {
                Update-HealthLog -path $healthLogPath_pass -message "SCCM Site found: $($mp.Name)" -WriteHost -color Green
            } else {
                Update-HealthLog -path $healthLogPath_pass -message "SMS_Authority.Name property not found." -WriteHost -color Red
                $allPassed = $false
            }

            # Check Client ID
            $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction SilentlyContinue
            if ( $ccmClient.ClientId ) {
                Update-HealthLog -path $healthLogPath_pass -message "SCCM Client Client ID found: $($ccmClient.ClientId)" -WriteHost -color Green
            } else {
                Update-HealthLog -path $healthLogPath_pass -message "Client Id property not found." -WriteHost -color Red
                $allPassed = $false
            }

            # Check Management Point FQDN
            if ( $mp.CurrentManagementPoint ) {
                Update-HealthLog -path $healthLogPath_pass -message "SCCM Management Point found: $($mp.CurrentManagementPoint)" -WriteHost -color Green
            } else {
                Update-HealthLog -path $healthLogPath_pass -message "Management Point property not found." -WriteHost -color Red
                $allPassed = $false
            }

            return $allPassed
        }

        # ------------------- IN SCOPE VARIABLES -------------------- #

        # Used in final health check
        $maxAttempts = 3
        $success = $false

        # Directories
        $localInstallerPath = "C:\drivers\ccm\ccmsetup"

        # Get site code. Might remove from script
        $siteCode = Get-SiteCode

        # -------------------- Reinstall SCCM -------------------- #

        Write-Host "(Step 9 of 11) Attempting reinstall." -ForegroundColor Cyan
        try {
            
            # Run SCCM installer silently with parameters. Wait for process to complete.
            if ( $siteCode -eq "DDS") { # DDS
                #$proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$siteCode /mp:SCANZ223 FSP=VOTCZ223" -PassThru -Verbose
                $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -PassThru
            }
            elseif ( $sitecode -eq "PCI" ) { # DPOS
                $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$siteCode" -PassThru -Verbose    
            }
            
            # Check install result. If failed, log error and exit with failure code.            
            $proc.WaitForExit()
            if ( $proc.ExitCode -ne 0 ){
                throw "SCCM install failed with exit code $($proc.exitcode)"
            }
            $message = "Reinstall complete."
            Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Cyan -return
            $message = "Waiting for service to be installed."
            Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost
            while ( -not ( Get-Service "ccmexec" -ErrorAction SilentlyContinue )) {
                Start-Sleep -Seconds 120
            }
            
            Update-HealthLog -path $healthLogPath_pass -message "Waiting for service to show running." -WriteHost
            while (( Get-Service "ccmexec").Status -ne "Running" ) {
                Start-Sleep -Seconds 120
            }
        }
        Catch{
            $message = "Install failed. Caught error: $_"
            Update-HealthLog -path $healthLogPath_pass -message $message -WriteHost -color Red -return
            return $false
        }

        # -------------------- REGISTER AND RUN CCMEVAL CHECK -------------------- #

        # CCMEval.exe actions
        Write-Host "(Step 10 of 11) Registering CcmEval. Running CcmEval check." -ForegroundColor Cyan
        C:\windows\ccm\CcmEval.exe /register
        Start-Sleep -Seconds 5
        C:\windows\ccm\CcmEval.exe /run

        # -------------------- RUN UNTIL ALL PASS OR TIMEOUT -------------------- #

        Write-Host "(Step 11 of 11) Running custom designed health check." -ForegroundColor Cyan

        Write-Host "Pausing for 60 seconds before verifying client is operating correctly."
        Start-Sleep -Seconds 60
        for ( $i = 1; $i -le $maxAttempts; $i++ ) {
            Write-Host "---- Health Check Attempt $i ----" -ForegroundColor Cyan

            if ( Start-HealthCheck ) {
                Write-Host "All SCCM health checks passed!" -ForegroundColor Green
                $success = $true
                break
            }

            if ( $i -lt $maxAttempts ) {
                Start-Sleep -Seconds 120
            }
        }

        if ( -not $success ) {
            Write-Host "Health checks did not pass after $maxAttempts attempts." -ForegroundColor Red
            return $false
        }

        # Write log to file
        $logFile = Join-Path $healthLogPath_pass "HealthCheck.txt"
        $healthLog | Out-File -Append -FilePath $logFile -Encoding UTF8
        return $true
    }

    # ----------------------------------------
    # End of Reinstall invoke-command
    # ----------------------------------------

    Write-Host "Completed work on $t" -ForegroundColor Green

    if ( $removalResult -eq $false ){
        "$t failed to uninstall" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
    }
    elseif ( $installResult -eq $false ) {
        "$t failed to install" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
    }
    elseif ( $removalResult -eq $true -and $installResult -eq $true ) {
        $t | Out-File -Append -FilePath $remediationSuccess -Encoding UTF8
    }
    if ( $failedToConnect ){
        foreach ( $f in $failedToConnect ){
            "$f failed to connect" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        }
    }
}

# ----------------------------------------
# End of For loop
# ----------------------------------------

Write-Host "Completed all target machines!!" -ForegroundColor Green