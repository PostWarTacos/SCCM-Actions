<#
#   Intent: Creates a scheduled task that will run a script. Script is used to check the health of the SCCM client.
#   Author: Matthew Wurtz
#   Date: 28-Feb-25
#   Updated: 04-Nov-25 - Added function to encode scripts and updated to use actual script files
#>

#===========================================
# FUNCTION TO ENCODE SCRIPTS TO BASE64
#===========================================
function ConvertTo-Base64EncodedScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath
    )
    
    if (-not (Test-Path $ScriptPath)) {
        throw "Script file not found: $ScriptPath"
    }
    
    $scriptContent = Get-Content $ScriptPath -Raw -Encoding UTF8
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
    $encodedScript = [Convert]::ToBase64String($bytes)
    
    return $encodedScript
}

#===========================================
# ENCODE SCRIPTS
#===========================================
# Build paths relative to the script's location
$healthCheckScript = Join-Path $PSScriptRoot "Check-SCCMHealth.ps1"
$removeScript = Join-Path $PSScriptRoot "Remove-SCCM.ps1"
$repairScript = Join-Path $PSScriptRoot "Reinstall-SCCM.ps1"

# Uses Base64 encoded string of the script for ease of use
$encodedCheck = ConvertTo-Base64EncodedScript -ScriptPath $healthCheckScript
$encodedRemove = ConvertTo-Base64EncodedScript -ScriptPath $removeScript
$encodedRepair = ConvertTo-Base64EncodedScript -ScriptPath $repairScript

#==========================================
# Global Variables for both Scheduled Tasks
#==========================================
# Compare hostname with API to determine timezone and store number
$uri = "https://ssdcorpappsrvt1.dpos.loc/esper/Device/AllStores"
$header = @{"accept" = "text/plain"}
$web = Invoke-WebRequest -Uri $uri -Headers $header
$db = $web.content | ConvertFrom-Json
$site = $db | select storeNumber,siteCode,ipSubnet,timeZone | where sitecode -eq ($(hostname).substring(1,4))

# Set day and time based on even/odd store number
if (( $site.storeNumber % 2 ) -eq 0 ){
    $dayOfTheWeek = "Tuesday" # EVEN
}
else{
    $dayOfTheWeek = "Thursday" # ODD
}

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $dayOfTheWeek -At 5am
$settings = New-ScheduledTaskSettingsSet -WakeToRun
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

#=============================
# Create Check-SCCMHealth Task
#=============================
$action = New-ScheduledTaskAction -Execute "powershell.exe"
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCheck"

$desc = "Will create a scheduled task to run based on even/odd store number. Task will run Check-SCCMHealth. Output will be stored locally until retrieved by server."


Register-ScheduledTask -TaskName "Check-SCCMHealthTask"
                       -Action $action
                       -Trigger $trigger
                       -settings $settings
                       -Principal $principal
                       -Description $desc

if(Get-ScheduledTask -TaskName Check-SCCMHealthTask){
    $result = "Created Check-SCCMHealth task"
} else{
    $result = "Failed to create Check-SCCMHealth task"
}
return $result

#========================
# Create Repair-SCCM Task
#========================
$action = New-ScheduledTaskAction -Execute "powershell.exe"
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedRepair"

$desc = "Will create a scheduled task to run only when triggered. When triggered, will call a script that will repair SCCM client on machine."


Register-ScheduledTask -TaskName "Repair-SCCMTask"
                        -Action $action
                        -settings $settings
                        -Principal $principal
                        -Description $desc

if(Get-ScheduledTask -TaskName Repair-SCCMTask){
    $result = "Created Repair-SCCM task"
} else{
    $result = "Failed to create Repair-SCCM task"
}
return $result