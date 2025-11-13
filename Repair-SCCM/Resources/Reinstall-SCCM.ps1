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

function Get-SiteCode{
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        if ( $domain -match "DDS" ) {
            $code = "DDS"
        }
        elseif ( $domain -match "DPOS" -or $domain -match "PCI" ) {
            $code = "PCI"
        }
        else {
            # Unknown domain - prompt for input with timeout
            Write-Warning "Unknown domain detected: $domain"
            Write-Host "Unable to automatically determine SCCM site code." -ForegroundColor Yellow
            Write-Host "Known site codes:" -ForegroundColor Cyan
            Write-Host "  - DDS (for DDS domains)" -ForegroundColor White
            Write-Host "  - PCI (for DPOS domains)" -ForegroundColor White
            
            do {
                $code = Get-UserInputWithTimeout -Prompt "Please enter the correct site code (DDS or PCI)" -TimeoutSeconds 10 -ValidValues @("DDS", "PCI", "DPOS")
                
                if ($null -eq $code) {
                    Write-Host "Invalid site code. Please enter 'DDS' or 'PCI'." -ForegroundColor Red
                    continue
                }
                
                # Convert DPOS to PCI for consistency
                if ($code -eq "DPOS") {
                    $code = "PCI"
                }
                
                break
            } while ($true)
            
            Write-Host "Using site code: $code" -ForegroundColor Green
        }
        return $code
    }
    catch {
        # Failed to get domain information - prompt for input
        Write-Error "Failed to get domain information: $_"
        Write-Host "Unable to automatically determine SCCM site code." -ForegroundColor Yellow
        Write-Host "Known site codes:" -ForegroundColor Cyan
        Write-Host "  - DDS (for DDS domains)" -ForegroundColor White
        Write-Host "  - PCI (for DPOS domains)" -ForegroundColor White
        
        do {
            $code = Get-UserInputWithTimeout -Prompt "Please enter the correct site code (DDS or PCI)" -TimeoutSeconds 10 -ValidValues @("DDS", "PCI", "DPOS")
            
            if ($null -eq $code) {
                Write-Host "Invalid site code. Please enter 'DDS' or 'PCI'." -ForegroundColor Red
                continue
            }
            
            # Convert DPOS to PCI for consistency
            if ($code -eq "DPOS") {
                $code = "PCI"
            }
            
            break
        } while ($true)
        
        Write-Host "Using site code: $code" -ForegroundColor Green
        return $code
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

function Test-HealthCheck {

    $allPassed = $true

    # Check if SCCM Client is installed
    if ( Test-Path "C:\Windows\CCM\CcmExec.exe" ) {
        Write-LogMessage -Level Success -Message "Found CcmExec.exe. SCCM installed."
    } else {
        Write-LogMessage -Level Error -Message "Cannot find CcmExec.exe."
        $allPassed = $false
    }

    # Check if SCCM Client Service is running
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

    # Check Client Version
    $smsClient = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue
    if ( $smsClient.ClientVersion ) {
        Write-LogMessage -Level Success -Message "SCCM Client Version: $($smsClient.ClientVersion)"
    } else {
        Write-LogMessage -Level Error -Message "Client Version not found."
        $allPassed = $false
    }

    # Check Management Point Site Name
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction SilentlyContinue
    if ( $mp.Name ) {
        Write-LogMessage -Level Success -Message "SCCM Site found: $($mp.Name)"
    } else {
        Write-LogMessage -Level Error -Message "SMS_Authority.Name property not found."
        $allPassed = $false
    }

    # Check Client ID
    $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction SilentlyContinue
    if ( $ccmClient.ClientId ) {
        Write-LogMessage -Level Success -Message "SCCM Client Client ID found: $($ccmClient.ClientId)"
    } else {
        Write-LogMessage -Level Error -Message "Client Id property not found."
        $allPassed = $false
    }

    # Check Management Point FQDN
    if ( $mp.CurrentManagementPoint ) {
        Write-LogMessage -Level Success -Message "SCCM Management Point found: $($mp.CurrentManagementPoint)"
    } else {
        Write-LogMessage -Level Error -Message "Management Point property not found."
        $allPassed = $false
    }

    return $allPassed
}

# ------------------- VARIABLES -------------------- #

# Creates an Arraylist which is mutable and easier to manipulate than an array.
$healthLog = [System.Collections.ArrayList]@()

# Used in final health check
$maxAttempts = 3
$success = $false

# Directories
$healthLogPath = "C:\drivers\ccm\logs"
$localInstallerPath = "C:\drivers\ccm\ccmsetup"

# Get site code. Might remove from script
$siteCode = Get-SiteCode

# -------------------- Reinstall SCCM -------------------- #

Write-Host "(Step 1 of 3) Attempting reinstall." -ForegroundColor Cyan
try {
    # DDS
    if ( $siteCode -eq "DDS") {
        #$proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$siteCode /mp:SCANZ223 FSP=VOTCZ223" -PassThru -Verbose
        $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -PassThru
    }
    # DPOS
    elseif ( $siteCode -eq "PCI" ) {
        $proc = Start-Process -FilePath "$localInstallerPath\ccmsetup.exe" -ArgumentList "/logon SMSSITECODE=$siteCode" -PassThru -Verbose    
    }
       
    $proc.WaitForExit()
    if ( $proc.ExitCode -ne 0 ){
        throw "SCCM install failed with exit code $($proc.exitcode)"
    }
    $message = "Reinstall complete."
    Write-LogMessage -Level Info -Message $message
    $message = "Waiting for service to be installed."
    Write-LogMessage -Level Info -Message $message
    while ( -not ( Get-Service "ccmexec" -ErrorAction SilentlyContinue )) {
        Start-Sleep -Seconds 120
    }
    
    Write-LogMessage -Level Info -Message "Waiting for service to show running."
    while (( Get-Service "ccmexec").Status -ne "Running" ) {
        Start-Sleep -Seconds 120
    }
}
Catch{
    $message = "Install failed. Caught error: $_"
    Write-LogMessage -Level Error -Message $message
    return $_
}

# -------------------- REGISTER AND RUN CCMEVAL CHECK -------------------- #

# CCMEval.exe actions
Write-Host "(Step 2 of 3) Registering CcmEval. Running CcmEval check." -ForegroundColor Cyan
C:\windows\ccm\CcmEval.exe /register
C:\windows\ccm\CcmEval.exe /run

# -------------------- RUN UNTIL ALL PASS OR TIMEOUT -------------------- #
Write-Host "(Step 3 of 3) Running custom health checks." -ForegroundColor Cyan
Write-Host "Pausing for 60 seconds before verifying client is operating correctly."
Start-Sleep -Seconds 60
for ( $i = 1; $i -le $maxAttempts; $i++ ) {
    Write-Host "---- Health Check Attempt $i ----" -ForegroundColor Cyan

    if ( Test-HealthCheck ) {
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
    return 201
}

