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
if ( Test-Path $clientPath ){
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec.exe. SCCM installed." ) | Out-Null
} Else {
	$healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Cannot find CcmExec.exe. SCCM Client is not installed." ) | Out-Null
    $corruption = "CcmExec.exe missing."
}
				
# Check if SCCM Client Service is running
$service = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
if ( $service.Status -eq 'Running' ){
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec service and it is running." ) | Out-Null
} Elseif ( $service.Status -ne 'Running' ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: Found CcmExec service but it is NOT running." ) | Out-Null
    $corruption = "CcmExec service not running."
} Else {
	$healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CcmExec service could not be found. SCCM Client may not be installed." ) | Out-Null
    $corruption = "CcmExec service missing."
}

# Check Client Version
$smsClient = Get-WmiObject -Namespace "root\ccm" -Class SMS_Client -ErrorAction SilentlyContinue
if ( $smsClient.ClientVersion ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client Version: $( $smsClient.ClientVersion )" ) | Out-Null
} else {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Client.ClientVersion class not found. SCCM Client may not be installed." ) | Out-Null
    $corruption = "Cannot determine client version."
}    

# Check Site Code
$mp = Get-WmiObject -Namespace "root\ccm" -Class SMS_Authority -ErrorAction SilentlyContinue
if ( $mp.Name ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Site found: $( $MP.Name )" ) | Out-Null
} else {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Authority.Name property not found. SCCM Client may not be installed." ) | Out-Null
    $corruption = "Site Code not found."
}

# Check Client ID
$ccmClient = Get-WmiObject -Namespace "root\ccm" -Class CCM_Client -ErrorAction SilentlyContinue
if ( $ccmClient.ClientId ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client Client ID found: $( $ccmClient.ClientId )" ) | Out-Null
} else {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: CCM_Client.ClientId property not found. SCCM Client may not be installed." ) | Out-Null
    $corruption = "Client ID not found."
}   
    
# Check Management Point Communication
$mp = Get-WmiObject -Namespace "root\ccm" -Class SMS_Authority -ErrorAction SilentlyContinue
if ( $mp.CurrentManagementPoint ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Management Point found: $( $mp.CurrentManagementPoint )" ) | Out-Null
} else {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SMS_Authority.CurrentManagementPoint property not found. SCCM Client may not be installed." ) | Out-Null
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
$lastWeekDate = $( Get-Date ).AddDays( -7 )

# Regex pattern to match log entries with dates
$pattern = '<time=".*?" date="(\d{2})-(\d{2})-(\d{4})"'

# Read the log file and filter logs from the last week
$filteredLogs = Get-Content $ccmEvalLogPath -Raw | Where-Object {
    if ( $_ -match $pattern ) {
        $logDate = Get-Date "$( $matches[1] )/$( $matches[2] )/$( $matches[3] )" -Format "MM/dd/yyyy"
        [datetime]$logDate -ge $lastWeekDate
    }
}

# Searches filtered logs (last week) for various strings that would point to a likely corrupt client.
$ccmEvalResults = $filteredLogs -split '<!' | Select-String -CaseSensitive:$false -Pattern `
    "Failed to", `
    "Unable to", `
    "WMI.*corrupt", `
    "CcmExec.*not running", `
    "Remediation failed", `
    "Client is not healthy", `
    "Required service.*not running", `
    "Firewall exception", `
    "Exit code: [1-9]", `
    "Error code", `
    "check: FAILED", `
    "Failed to connect", `
    "Failed to get"

if ( $ccmEvalResults ) {
    $healthLog.Add( "[$(get-date -Format "dd-MMM-yy HH:mm:ss")] Message: SCCM Client health check failed per CCMEval logs." ) | Out-Null
    $mostRecentFail = "$( $ccmEvalResults | select -last 1 )."
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
    Start-ScheduledTask "Repair-SCCMTask" # Comment this line for JUST a health check through CC.
}

if ( -not ( Test-Path $healthLogPath )){
    mkdir $healthLogPath
}

$healthLog >> $healthLogPath\HealthCheck.txt
return $results