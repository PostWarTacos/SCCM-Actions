<#
#   Intent: Ran from Collection Commander. Will check 7 different points to verify the health of SCCM client
#   Date: 24-Feb-25
#   Author: Matthew Wurtz
#>

#====================
# VARIABLES AND MKDIR
#====================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [bool]$ConsoleOutput = $false
)

# Detect if script is run via Invoke-SCCMRepair.ps1 and set ConsoleOutput accordingly
if ($MyInvocation.InvocationName -eq 'Invoke-SCCMRepair.ps1' -or $MyInvocation.MyCommand.Name -eq 'Invoke-SCCMRepair.ps1') {
    $ConsoleOutput = $true
}

#====================
# VARIABLES AND MKDIR
#====================

$healthLog = [System.Collections.ArrayList]@()
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
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec.exe. SCCM installed.") | Out-Null
            if ($ConsoleOutput) { Write-Host "Found CcmExec.exe. SCCM installed." }
    } else {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Cannot find CcmExec.exe. SCCM Client is not installed." ) | Out-Null
<<<<<<< HEAD
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmExec.exe missing.'}
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error checking CcmExec.exe: $_" ) | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Error checking SCCM installation.'}
=======
            if ($ConsoleOutput) { Write-Host "Cannot find CcmExec.exe. SCCM Client is not installed." }
        $corruption.Add("CcmExec.exe missing.") | Out-Null
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error checking CcmExec.exe: $_" ) | Out-Null
        if ($ConsoleOutput) { Write-Host "Error checking CcmExec.exe: $_" }
    $corruption.Add("Error checking SCCM installation.") | Out-Null
>>>>>>> 2b54cceeb9b3428d88c5e1a5d3657b2c7b823a7d
}
				
# Check if SCCM Client Service is running
try {
    $service = Get-Service -Name CcmExec -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CcmExec service is running.") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CcmExec service is not running. Status: $($service.Status)") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='CcmExec service not running.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format \"dd-MMM-yy HH:mm:ss\")] Message: CcmExec service not found: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmExec service missing.'}
}

# Check Client Version
try {
    $smsClient = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
    if ($smsClient -and $smsClient.ClientVersion) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client Version: $($smsClient.ClientVersion)") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Client.ClientVersion is null or empty.") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='Client version not available.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing SMS_Client class: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='SMS_Client class inaccessible.'}
}    

# Check Site Code
try {
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction Stop
    if ($mp -and $mp.Name) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Site Code: $($mp.Name)") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Authority.Name is null or empty.") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Site Code not available.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing SMS_Authority class: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='SMS_Authority class inaccessible.'}
}

# Check Client ID
try {
    $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction Stop
    if ($ccmClient -and $ccmClient.ClientId) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client ID: $($ccmClient.ClientId)") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CCM_Client.ClientId is null or empty.") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Client ID not available.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing CCM_Client class: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CCM_Client class inaccessible.'}
}   

# Check ClientSDK namespace for task sequence capability
try {
    $clientSDKTest = Get-CimInstance -Namespace "root\ccm\ClientSDK" -ClassName CCM_Application -ErrorAction Stop | Select-Object -First 1
    if ($clientSDKTest) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: ClientSDK namespace accessible.") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: ClientSDK namespace accessible but no applications found.") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='ClientSDK namespace empty.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing ClientSDK namespace: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='ClientSDK namespace corrupt.'}
}

# Check Policy namespace for task sequence policies
try {
    $policyResult = Get-CimInstance -Namespace "root\ccm\Policy\Machine\ActualConfig" -ClassName CCM_TaskSequence -ErrorAction Stop
    if ($policyResult -and $policyResult.Count -gt 0) {
        $policyCount = $policyResult.Count
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Policy namespace accessible. Found $policyCount task sequences.") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Policy namespace accessible but no task sequences found.") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Policy namespace empty.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing Policy namespace: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Policy namespace corrupt.'}
}

# Check SoftMgmtAgent namespace for execution tracking
try {
    $execHistoryTest = Get-CimInstance -Namespace "root\ccm\SoftMgmtAgent" -ClassName CCM_ExecutionHistory -ErrorAction Stop | Select-Object -First 1
    if ($execHistoryTest) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SoftMgmtAgent namespace accessible.") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SoftMgmtAgent namespace accessible but no execution history found.") | Out-Null
        # Note: Empty execution history is normal, so no corruption flag
    }
} catch {
    # Check if it's just an "Invalid class" error which is common and not corruption
    if ($_.Exception.Message -match "Invalid class") {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SoftMgmtAgent namespace accessible but no CCM_ExecutionHistory class.") | Out-Null
        # Note: Invalid class is often normal, so no corruption flag
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing SoftMgmtAgent namespace: $_") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='SoftMgmtAgent namespace corrupt.'}
    }
}

# Check if client can access task sequence execution requests
try {
    $tsExecTest = Get-CimInstance -Namespace "root\ccm\SoftMgmtAgent" -ClassName CCM_TSExecutionRequest -ErrorAction Stop | Select-Object -First 1
    if ($tsExecTest) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: TS execution request tracking accessible.") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: TS execution request tracking accessible but no requests found.") | Out-Null
        # Note: Empty execution requests is normal, so no corruption flag
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing CCM_TSExecutionRequest class: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='TS execution request class corrupt.'}
}

# Check Management Point Communication
try {
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction Stop
    if ($mp -and $mp.CurrentManagementPoint) {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Management Point: $($mp.CurrentManagementPoint)") | Out-Null
    } else {
        $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Authority.CurrentManagementPoint is null or empty.") | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Management Point not available.'}
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing Management Point information: $_") | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='Management Point information inaccessible.'}
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
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error reading CCMEval log: $_") | Out-Null
    $ccmEvalResults = $null
}

if ( $ccmEvalResults ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client health check failed per CCMEval logs." ) | Out-Null
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
            $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Context: Health check context errors: $allContext") | Out-Null
        } else {
            # No context errors found - indicate this in the failure message
            $failMsg = "Client Health Check: FAILED. No additional info in logs."
        }
    }
    
    # Outputs all fail messages within last week to healthcheck.txt
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: $( $ccmEvalResults )." ) | Out-Null
    $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='Corruption in Eval log.'}
} else {
    # Check why CCMEval results are empty - could indicate missing SCCM installation
    if (-not (Test-Path $ccmEvalLogPath)) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CCMEval log not found. SCCM may not be installed or functioning." ) | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Warning'; Message='CCMEval log missing.'}
    } elseif (-not (Test-Path "C:\Windows\ccm\CcmEval.exe")) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CcmEval.exe not found. SCCM installation incomplete." ) | Out-Null
        $healthMessages += [PSCustomObject]@{Severity='Critical'; Message='CcmEval.exe missing.'}
    } else {
        # Log exists but no recent errors found - this could be genuinely healthy
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CCMEval log exists but no recent errors found in last 7 days." ) | Out-Null
    }
}

#===============
# REPORT RESULTS (PRIORITIZED)
#===============

function Get-SeverityRank {
    param($severity)
    switch ($severity) {
        'Critical' { return 1 }
        'Warning' { return 2 }
        'Informational' { return 3 }
        default { return 99 }
    }
}


if ($healthMessages.Count -eq 0) {
    $results = "Healthy Client"
} elseif ($healthMessages.Count -eq 1) {
    # Single issue, check for Eval log and $failMsg
    if ($healthMessages[0].Message -eq "Corruption in Eval log." -and $failMsg) {
        $results = "Corrupt Client. $failMsg"
    } else {
        $results = "Corrupt Client. [$($healthMessages[0].Severity)] $($healthMessages[0].Message)"
    }
} else {
    $sortedMessages = $healthMessages | Sort-Object @{Expression={Get-SeverityRank $_.Severity}}, @{Expression={$_.Message}}
    $hasEvalError = $healthMessages | Where-Object { $_.Message -eq "Corruption in Eval log." }
    if (-not $hasEvalError) {
        # No eval error, show most critical + count
        $mostCritical = $sortedMessages[0]
        $additionalCount = $healthMessages.Count - 1
        $results = "Corrupt Client. [$($mostCritical.Severity)] $($mostCritical.Message) (+ $additionalCount more issues in log)"
    } else {
        # Has eval error, find most recent non-eval error
        $nonEvalMessages = $sortedMessages | Where-Object { $_.Message -ne "Corruption in Eval log." }
        if ($nonEvalMessages.Count -gt 0) {
            $mostRecentNonEval = $nonEvalMessages[0]
            $additionalCount = $healthMessages.Count - 1
            $results = "Corrupt Client. [$($mostRecentNonEval.Severity)] $($mostRecentNonEval.Message) (+ $additionalCount more issues in log)"
        } elseif ($failMsg) {
            $results = "Corrupt Client. $failMsg"
        } else {
            $results = "Corrupt Client. Corruption in Eval log."
        }
    }
}

if ( -not ( Test-Path $healthLogPath )){
    mkdir $healthLogPath
}

$healthLog >> $healthLogPath\HealthCheck.txt
return $results
