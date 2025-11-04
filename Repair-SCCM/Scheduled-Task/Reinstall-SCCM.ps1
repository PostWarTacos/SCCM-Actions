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
        [string]$Color
    )

    $healthLog.Add("[$(Get-Date -Format 'dd-MMM-yy HH:mm:ss')] Message: $message") | Out-Null

    if ( $PSBoundParameters.ContainsKey('WriteHost') -and $PSBoundParameters.ContainsKey('Color') ) {
        Write-Host $message -ForegroundColor $Color
    }
    elseif ( $PSBoundParameters.ContainsKey('WriteHost') ) {
        Write-Host $Message
    }
}

function Test-HealthCheck {

    $allPassed = $true

    # Check if SCCM Client is installed
    if ( Test-Path "C:\Windows\CCM\CcmExec.exe" ) {
        Update-HealthLog -path $healthLogPath -message "Found CcmExec.exe. SCCM installed." -WriteHost -color Green
    } else {
        Update-HealthLog -path $healthLogPath -message "Cannot find CcmExec.exe." -WriteHost -color Red
        $allPassed = $false
    }

    # Check if SCCM Client Service is running
    $service = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    if ( $service.Status -eq 'Running' ) {
        Update-HealthLog -path $healthLogPath -message "Found CcmExec service and it is running." -WriteHost -color Green
    } elseif ( $service.Status -ne 'Running' ) {
        Update-HealthLog -path $healthLogPath -message "Found CcmExec service but it is NOT running." -WriteHost -color Red
        $allPassed = $false
    } else {
        Update-HealthLog -path $healthLogPath -message "CcmExec service could not be found." -WriteHost -color Red
        $allPassed = $false
    }

    # Check Client Version
    $smsClient = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue
    if ( $smsClient.ClientVersion ) {
        Update-HealthLog -path $healthLogPath -message "SCCM Client Version: $($smsClient.ClientVersion)" -WriteHost -color Green
    } else {
        Update-HealthLog -path $healthLogPath -message "Client Version not found." -WriteHost -color Red
        $allPassed = $false
    }

    # Check Management Point Site Name
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction SilentlyContinue
    if ( $mp.Name ) {
        Update-HealthLog -path $healthLogPath -message "SCCM Site found: $($mp.Name)" -WriteHost -color Green
    } else {
        Update-HealthLog -path $healthLogPath -message "SMS_Authority.Name property not found." -WriteHost -color Red
        $allPassed = $false
    }

    # Check Client ID
    $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction SilentlyContinue
    if ( $ccmClient.ClientId ) {
        Update-HealthLog -path $healthLogPath -message "SCCM Client Client ID found: $($ccmClient.ClientId)" -WriteHost -color Green
    } else {
        Update-HealthLog -path $healthLogPath -message "Client Id property not found." -WriteHost -color Red
        $allPassed = $false
    }

    # Check Management Point FQDN
    if ( $mp.CurrentManagementPoint ) {
        Update-HealthLog -path $healthLogPath -message "SCCM Management Point found: $($mp.CurrentManagementPoint)" -WriteHost -color Green
    } else {
        Update-HealthLog -path $healthLogPath -message "Management Point property not found." -WriteHost -color Red
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

Write-Host "(Step 7 of 8) Attempting reinstall." -ForegroundColor Cyan
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
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Cyan
    $message = "Waiting for service to be installed."
    Update-HealthLog -path $healthLogPath -message $message -WriteHost
    while ( -not ( Get-Service "ccmexec" -ErrorAction SilentlyContinue )) {
        Start-Sleep -Seconds 120
    }
    
    Update-HealthLog -path $healthLogPath -message "Waiting for service to show running." -WriteHost
    while (( Get-Service "ccmexec").Status -ne "Running" ) {
        Start-Sleep -Seconds 120
    }
}
Catch{
    $message = "Install failed. Caught error: $_"
    Update-HealthLog -path $healthLogPath -message $message -WriteHost -color Red
    return $_
}

# -------------------- REGISTER AND RUN CCMEVAL CHECK -------------------- #

# CCMEval.exe actions
Write-Host "(Step 8 of 8) Registering CcmEval. Running CcmEval check." -ForegroundColor Cyan
C:\windows\ccm\CcmEval.exe /register
C:\windows\ccm\CcmEval.exe /run

# -------------------- RUN UNTIL ALL PASS OR TIMEOUT -------------------- #
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

$healthLog >> $healthLogPath\HealthCheck.txt