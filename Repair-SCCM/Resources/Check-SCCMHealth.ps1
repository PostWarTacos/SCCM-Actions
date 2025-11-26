<#
#   Intent: Ran from Collection Commander. Will check 7 different points to verify the health of SCCM client
#   Date: 24-Feb-25
#   Author: Matthew Wurtz
#>

[CmdletBinding()]
param()

# Set strict mode to catch errors early
$ErrorActionPreference = 'Continue'

# Embedded logging function
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory)]
        [string]$Message,
        [Parameter(Position=1)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Default")]
        [string]$Level,
        [string]$LogFile = "$global:healthLogPath\HealthCheck.txt"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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
    
    # Only write to console if we're in an interactive session (not via Invoke-Command)
    $isRemoteSession = [bool]$PSSenderInfo
    if ($PSBoundParameters.ContainsKey('Level') -and -not $isRemoteSession) {
        switch ($Level) {
            "Default" { Write-Host $logEntry -ForegroundColor DarkGray }
            "Info"    { Write-Host $logEntry -ForegroundColor White }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            "Error"   { Write-Host $logEntry -ForegroundColor Red }
            "Success" { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -ErrorAction Stop
        } catch {
            # Silently continue if log file write fails in remote session
        }
    }
}

#====================
# VARIABLES AND MKDIR
#====================

$healthMessages = @()
$healthLogPath = "C:\drivers\CCM\Logs\"

If( -not ( Test-Path $healthLogPath )) {
    mkdir $healthLogPath
}

#=====================
# HEALTH CHECK ACTIONS
#=====================


# Check if SCCM Client is installed
$clientPath = "C:\Windows\CCM\CcmExec.exe"
try {
    if (Test-Path $clientPath) {
        Write-LogMessage -Message "Found CcmExec.exe. SCCM installed." -Level Info
    } else {
        Write-LogMessage -Message "Cannot find CcmExec.exe. SCCM Client is not installed." -Level Error
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmExec.exe missing.'; Priority=1}
    }
} catch {
    Write-LogMessage -Message "Error checking CcmExec.exe: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Error checking SCCM installation.'}
}
				
# Check if SCCM Client Service is running
try {
    $service = Get-Service -Name CcmExec -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        Write-LogMessage -Message "CcmExec service is running." -Level Info
    } else {
        Write-LogMessage -Message "CcmExec service is not running. Status: $($service.Status)" -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmExec service stopped.'; Priority=2}
    }
} catch {
    Write-LogMessage -Message "CcmExec service not found: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmExec service missing.'; Priority=3}
}

# Check Client Version
try {
    $smsClient = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
    if ($smsClient -and $smsClient.ClientVersion) {
        Write-LogMessage -Message "SCCM Client Version: $($smsClient.ClientVersion)" -Level Info
    } else {
        Write-LogMessage -Message "SMS_Client.ClientVersion is null or empty." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='Client version not available.'; Priority=50}
    }
} catch {
    Write-LogMessage -Message "Error accessing SMS_Client class: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='SMS_Client class inaccessible.'; Priority=51}
}    

# Check Site Code
try {
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction Stop
    if ($mp -and $mp.Name) {
        Write-LogMessage -Message "SCCM Site Code: $($mp.Name)" -Level Info
    } else {
        Write-LogMessage -Message "SMS_Authority.Name is null or empty." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Site Code not available.'; Priority=4}
    }
} catch {
    Write-LogMessage -Message "Error accessing SMS_Authority class: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='SMS_Authority class inaccessible.'}
}

# Check Client ID
try {
    $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction Stop
    if ($ccmClient -and $ccmClient.ClientId) {
        Write-LogMessage -Message "SCCM Client ID: $($ccmClient.ClientId)" -Level Info
    } else {
        Write-LogMessage -Message "CCM_Client.ClientId is null or empty." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Client ID not available.'; Priority=6}
    }
} catch {
    Write-LogMessage -Message "Error accessing CCM_Client class: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CCM_Client class inaccessible.'; Priority=7}
}   

# Check ClientSDK namespace for task sequence capability
try {
    $clientSDKTest = Get-CimInstance -Namespace "root\ccm\ClientSDK" -ClassName CCM_Application -ErrorAction Stop | Select-Object -First 1
    if ($clientSDKTest) {
        Write-LogMessage -Message "ClientSDK namespace accessible." -Level Info
    } else {
        Write-LogMessage -Message "ClientSDK namespace accessible but no applications found." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='ClientSDK namespace empty.'; Priority=8}
    }
} catch {
    Write-LogMessage -Message "Error accessing ClientSDK namespace: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='ClientSDK namespace corrupt.'; Priority=9}
}

# Check Policy namespace for task sequence policies
try {
    $policyResult = Get-CimInstance -Namespace "root\ccm\Policy\Machine\ActualConfig" -ClassName CCM_TaskSequence -ErrorAction Stop
    if ($policyResult -and $policyResult.Count -gt 0) {
        $policyCount = $policyResult.Count
        Write-LogMessage -Message "Policy namespace accessible. Found $policyCount task sequences." -Level Info
    } else {
        Write-LogMessage -Message "Policy namespace accessible but no task sequences found." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Policy namespace empty.'; Priority=10}
    }
} catch {
    Write-LogMessage -Message "Error accessing Policy namespace: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Policy namespace corrupt.'; Priority=11}
}

# Check SoftMgmtAgent namespace for execution tracking
try {
    $execHistoryTest = Get-CimInstance -Namespace "root\ccm\SoftMgmtAgent" -ClassName CCM_ExecutionHistory -ErrorAction Stop | Select-Object -First 1
    if ($execHistoryTest) {
        Write-LogMessage -Message "SoftMgmtAgent namespace accessible." -Level Info
    } else {
        Write-LogMessage -Message "SoftMgmtAgent namespace accessible but no execution history found." -Level Info
        # Note: Empty execution history is normal, so no corruption flag
    }
} catch {
    # Check if it's just an "Invalid class" error which is common and not corruption
    if ($_.Exception.Message -match "Invalid class") {
        Write-LogMessage -Message "SoftMgmtAgent namespace accessible but no CCM_ExecutionHistory class." -Level Info
        # Note: Invalid class is often normal, so no corruption flag
    } else {
        Write-LogMessage -Message "Error accessing SoftMgmtAgent namespace: $_" -Level Error
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='SoftMgmtAgent namespace corrupt.'; Priority=12}
    }
}

# Check if client can access task sequence execution requests
try {
    $tsExecTest = Get-CimInstance -Namespace "root\ccm\SoftMgmtAgent" -ClassName CCM_TSExecutionRequest -ErrorAction Stop | Select-Object -First 1
    if ($tsExecTest) {
        Write-LogMessage -Message "TS execution request tracking accessible." -Level Info
    } else {
        Write-LogMessage -Message "TS execution request tracking accessible but no requests found." -Level Info
        # Note: Empty execution requests is normal, so no corruption flag
    }
} catch {
    Write-LogMessage -Message "Error accessing CCM_TSExecutionRequest class: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='TS execution request class corrupt.'; Priority=13}
}

# Check Management Point Communication
try {
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction Stop
    if ($mp -and $mp.CurrentManagementPoint) {
        Write-LogMessage -Message "Management Point: $($mp.CurrentManagementPoint)" -Level Info
    } else {
        Write-LogMessage -Message "SMS_Authority.CurrentManagementPoint is null or empty." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Management Point not available.'; Priority=14}
    }
} catch {
    Write-LogMessage -Message "Error accessing Management Point information: $_" -Level Error
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Management Point information inaccessible.'; Priority=15}
}

#================
# CCM CLIENT EVAL
#================

$ccmEvalLogPath = "C:\Windows\CCM\Logs\CCMEval.log"

# Generate the log if it doesn't exist and re-register it as scheduled task
if ( -not ( Test-Path $ccmEvalLogPath )) {
    if ( test-path "C:\Windows\ccm\CcmEval.exe" ){
        C:\Windows\ccm\CcmEval.exe /register
        C:\Windows\ccm\CcmEval.exe /run
        Start-Sleep -Seconds 120
    }
}

# Get the current date and calculate the date a week ago
$lastWeekDate = (Get-Date).AddDays(-7)

# Improved log parsing with better error handling
try {
    if (Test-Path $ccmEvalLogPath) {
        # Read the log file with better encoding handling
        $logContent = Get-Content $ccmEvalLogPath -Raw -Encoding UTF8 -ErrorAction Stop
        
        # Split into individual log entries
        $logEntries = $logContent -split '<!\[LOG\['
        
        # Filter logs from the last week with improved date parsing
        $recentLogs = $logEntries | Where-Object {
            if ($_ -match '<time="[^"]*"\s+date="(\d{2})-(\d{2})-(\d{4})"') {
                try {
                    $logDate = Get-Date "$($matches[2])/$($matches[1])/$($matches[3])" -ErrorAction Stop
                    return $logDate -ge $lastWeekDate
                } catch {
                    # If date parsing fails, include the entry to be safe
                    return $true
                }
            }
            return $false
        }
        
        # Search for error patterns in recent logs
        $errorPatterns = @(
            "Failed to",
            "Unable to", 
            "WMI.*corrupt",
            "CcmExec.*not running",
            "Remediation failed",
            "Client is not healthy",
            "Required service.*not running",
            "Firewall exception",
            "Exit code: [1-9]",
            "Error code",
            ".*check: FAILED",
            "Failed to connect",
            "Failed to get"
        )
        
        # Exclude common false positives
        $excludePatterns = @(
            "Failed to get SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware",
            "DisableIntrusionPreventionSystem"
        )
        
        $ccmEvalResults = $recentLogs | Select-String -Pattern ($errorPatterns -join '|') -CaseSensitive:$false | 
            Where-Object { 
                $line = $_.Line
                $shouldExclude = $false
                foreach ($exclude in $excludePatterns) {
                    if ($line -match $exclude) {
                        $shouldExclude = $true
                        break
                    }
                }
                return -not $shouldExclude
            }
    } else {
        $ccmEvalResults = $null
    }
} catch {
    Write-LogMessage -Message "Error reading CCMEval log: $_" -Level Error
    $ccmEvalResults = $null
}

if ( $ccmEvalResults ) {
    Write-LogMessage -Message "SCCM Client health check failed per CCMEval logs." -Level Warning
    $mostRecentFail = "$( $ccmEvalResults | Select-Object -Last 1 )"
    
    # Try multiple extraction patterns to get meaningful failure info
    if ($mostRecentFail -match 'LOG\[(.*?)\]LOG') {
        $failMsg = $matches[1].Trim()
    } elseif ($mostRecentFail -match '<!\[LOG\[(.*?)$') {
        $failMsg = $matches[1].Trim()
    } else {
        # If no specific pattern matches, try to extract the meaningful part
        $cleanFail = $mostRecentFail -replace '<!\[LOG\[', '' -replace '\]LOG.*$', ''
        if ($cleanFail.Length -gt 10) {
            $failMsg = $cleanFail.Trim()
        }
    }
    
    # If we found "Client Health Check: Failed", try to find preceding context for why it failed
    if ($mostRecentFail -match "Client Health Check.*FAILED") {
        # Look for the most recent failure before this summary message
        $contextErrors = $ccmEvalResults | Select-Object -SkipLast 1 | Select-Object -Last 3
        
        if ($contextErrors -and $contextErrors.Count -gt 0) {
            # Find the most recent context error that's different from the most recent fail
            $mostRecentContext = $null
            for ($i = $contextErrors.Count - 1; $i -ge 0; $i--) {
                $cleanContext = $contextErrors[$i] -replace '<!\[LOG\[', '' -replace '\]LOG.*$', ''
                $cleanMostRecent = $mostRecentFail -replace '<!\[LOG\[', '' -replace '\]LOG.*$', ''
                
                # If this context error is different from the most recent fail, use it
                if ($cleanContext -ne $cleanMostRecent -and $cleanContext.Length -gt 10) {
                    $mostRecentContext = $cleanContext.Trim()
                    break
                }
            }
            
            if ($mostRecentContext) {
                $failMsg = $mostRecentContext
            } else {
                # All context errors match the most recent fail - no unique context
                $failMsg = "Client Health Check: FAILED. No additional info in logs."
            }
            
            # Log all context errors to the health log for full details
            $allContext = ($contextErrors | ForEach-Object { 
                $_ -replace '<!\[LOG\[', '' -replace '\]LOG.*$', '' 
            }) -join "; "
            Write-LogMessage -Message "Health check context errors: $allContext" -Level Info
        } else {
            # No context errors found - indicate this in the failure message
            $failMsg = "Client Health Check: FAILED. No additional info in logs."
        }
    }
    
    # Outputs all fail messages within last week to healthcheck.txt
    Write-LogMessage -Message "$( $ccmEvalResults )." -Level Info
    $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='Corruption in Eval log.'; Priority=53}
} else {
    # Check why CCMEval results are empty - could indicate missing SCCM installation
    if (-not (Test-Path $ccmEvalLogPath)) {
        Write-LogMessage -Message "CCMEval log not found. SCCM may not be installed or functioning." -Level Warning
        $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='CCMEval log missing.'; Priority=52}
    } elseif (-not (Test-Path "C:\Windows\ccm\CcmEval.exe")) {
        Write-LogMessage -Message "CcmEval.exe not found. SCCM installation incomplete." -Level Error
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmEval.exe missing.'; Priority=18}
    } else {
        # Log exists but no recent errors found - this could be genuinely healthy
        Write-LogMessage -Message "CCMEval log exists but no recent errors found in last 7 days." -Level Info
    }
}

#===============
# REPORT RESULTS (NUMBERED PRIORITY)
#===============

if ($healthMessages.Count -eq 0) {
    $results = "Healthy"
} elseif ($healthMessages.Count -eq 1) {
    if ($healthMessages[0].Message -eq "Corruption in Eval log." -and $failMsg) {
        $results = "Corrupt Client: $failMsg"
    } else {
        $results = "Corrupt Client: [$($healthMessages[0].Severity)] $($healthMessages[0].Message)"
    }
} else {
    $sortedMessages = $healthMessages | Sort-Object Priority, Severity, Message
    $topError = $sortedMessages[0]
    $additionalCount = $healthMessages.Count - 1
    $results = "Corrupt Client: [$($topError.Severity)] $($topError.Message) (+ $additionalCount more issues)"
}

if ( -not ( Test-Path $healthLogPath )){
    mkdir $healthLogPath | Out-Null
}

return $results
