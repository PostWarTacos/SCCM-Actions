<#
#   Intent: Ran from Collection Commander. Will check 7 different points to verify the health of SCCM client
#   Date: 24-Feb-25
#   Author: Matthew Wurtz
#>

#====================
# VARIABLES AND MKDIR
#====================

$healthLog = [System.Collections.ArrayList]@()
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
    if ( Test-Path $clientPath ){
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec.exe. SCCM installed." ) | Out-Null
    } else {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Cannot find CcmExec.exe. SCCM Client is not installed." ) | Out-Null
        $corruption = "CcmExec.exe missing."
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error checking CcmExec.exe: $_" ) | Out-Null
    $corruption = "Error checking SCCM installation."
}
				
# Check if SCCM Client Service is running
try {
    $service = Get-Service -Name CcmExec -ErrorAction Stop
    if ( $service.Status -eq 'Running' ){
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec service and it is running." ) | Out-Null
    } elseif ( $service.Status -ne 'Running' ) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec service but it is NOT running." ) | Out-Null
        $corruption = "CcmExec service not running."
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CcmExec service could not be found. SCCM Client may not be installed." ) | Out-Null
    $corruption = "CcmExec service missing."
}

# Check Client Version
try {
    $smsClient = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
    if ( $smsClient.ClientVersion ) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client Version: $( $smsClient.ClientVersion )" ) | Out-Null
    } else {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Client.ClientVersion class not found. SCCM Client may not be installed." ) | Out-Null
        $corruption = "Cannot determine client version."
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing SMS_Client: $_" ) | Out-Null
    $corruption = "Cannot determine client version."
}    

# Check Site Code
try {
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction Stop
    if ( $mp.Name ) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Site found: $( $MP.Name )" ) | Out-Null
    } else {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Authority.Name property not found. SCCM Client may not be installed." ) | Out-Null
        $corruption = "Site Code not found."
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing SMS_Authority: $_" ) | Out-Null
    $corruption = "Site Code not found."
}

# Check Client ID
try {
    $ccmClient = Get-CimInstance -Namespace "root\ccm" -ClassName CCM_Client -ErrorAction Stop
    if ( $ccmClient.ClientId ) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client Client ID found: $( $ccmClient.ClientId )" ) | Out-Null
    } else {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CCM_Client.ClientId property not found. SCCM Client may not be installed." ) | Out-Null
        $corruption = "Client ID not found."
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing CCM_Client: $_" ) | Out-Null
    $corruption = "Client ID not found."
}   
    
# Check Management Point Communication
try {
    $mp = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Authority -ErrorAction Stop
    if ( $mp.CurrentManagementPoint ) {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Management Point found: $( $mp.CurrentManagementPoint )" ) | Out-Null
    } else {
        $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Authority.CurrentManagementPoint property not found. SCCM Client may not be installed." ) | Out-Null
        $corruption = "Failed to contact MP."
    }
} catch {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error accessing Management Point: $_" ) | Out-Null
    $corruption = "Failed to contact MP."
}

#================
# CCM CLIENT EVAL
#================

$ccmEvalLogPath = "C:\Windows\CCM\Logs\CCMEval.log"

# Generate the log if it doesn't exist and re-register it as scheduled task
if ( -not ( Test-Path $ccmEvalLogPath )) {
    C:\Windows\ccm\CcmEval.exe /register
    C:\Windows\ccm\CcmEval.exe /run
    Start-Sleep -Seconds 120
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
            "check: FAILED",
            "Failed to connect",
            "Failed to get"
        )
        
        $ccmEvalResults = $recentLogs | Select-String -Pattern ($errorPatterns -join '|') -CaseSensitive:$false
    } else {
        $ccmEvalResults = $null
    }
} catch {
    $healthLog.Add("[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Error reading CCMEval log: $_") | Out-Null
    $ccmEvalResults = $null
}

if ( $ccmEvalResults ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client health check failed per CCMEval logs." ) | Out-Null
    $mostRecentFail = "$( $ccmEvalResults | Select-Object -Last 1 )."
    if ($mostRecentFail -match 'LOG\[(.*?)\]LOG') {
        $failMsg = $matches[1]
    }
    # Outputs all fail messages within last week to healthcheck.txt
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: $( $ccmEvalResults )." ) | Out-Null
    $corruption = "Corruption in Eval log."
} else {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client passed health check per CCMEval logs." ) | Out-Null
}

#===============
# REPORT RESULTS
#===============

if ( -not ( $corruption )){
    $results = "Healthy Client"
} else{
    if( $corruption -and $failMsg ) {
        $results = "$corruption $failMsg."
    }
    else {
        $results = "Corrupt Client. $corruption"
    }
    Start-ScheduledTask "Remove-SCCMTask" # Triggers Remove-SCCM task when health check fails.
}

if ( -not ( Test-Path $healthLogPath )){
    mkdir $healthLogPath
}

$healthLog >> $healthLogPath\HealthCheck.txt
return $results