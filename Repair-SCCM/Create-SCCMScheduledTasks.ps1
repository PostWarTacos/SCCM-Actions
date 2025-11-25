<#
<#
#   Intent: Creates scheduled tasks that run SCCM resource scripts in non-interactive PowerShell sessions (automation). Scheduled tasks pass arguments like -Interactive $false to ensure scripts run in automation mode and return exit codes (0 for success, 1 for failure) for reliable status detection.
#   Author: Matthew Wurtz
#   Date: 28-Feb-25
#   Updated: 20-Nov-25 - Clarified scheduled task mode and exit code handling in comments
#>
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
# VALIDATE AND ENCODE SCRIPTS
#===========================================
# Build paths relative to the script's location in Resources folder
$resourcesPath = Join-Path $PSScriptRoot "Resources"
$healthCheckScript = Join-Path $resourcesPath "Check-SCCMHealth.ps1"
$removeScript = Join-Path $resourcesPath "Remove-SCCM.ps1"
$reinstallScript = Join-Path $resourcesPath "Reinstall-SCCM.ps1"

# Validate script paths exist before encoding
$scriptPaths = @{
    'healthCheckScript' = $healthCheckScript
    'removeScript' = $removeScript
    'reinstallScript' = $reinstallScript
}

foreach ($name in $scriptPaths.Keys) {
    if (-not (Test-Path $scriptPaths[$name])) {
        throw "Required script file not found: $($scriptPaths[$name])"
    }
}

# Use Base64 encoded strings for reliable scheduled task execution
$encodedCheck = ConvertTo-Base64EncodedScript -ScriptPath $healthCheckScript
$encodedRemove = ConvertTo-Base64EncodedScript -ScriptPath $removeScript
$encodedReinstall = ConvertTo-Base64EncodedScript -ScriptPath $reinstallScript

# Initialize results array to collect all task creation results
$results = @()

#==========================================
# Global Variables for both Scheduled Tasks
#==========================================
# Compare hostname with API to determine timezone and store number with robust fallback
$dayOfTheWeek = "Tuesday" # Default fallback

try {
    # Extract store code from hostname (assumes format like "S1234")
    $hostname = $env:COMPUTERNAME
    if ($hostname -match '^S?(\d{4})') {
        $storeCode = $matches[1]
        
        # Attempt API call with timeout and retries
        $uri = "https://ssdcorpappsrvt1.dpos.loc/esper/Device/AllStores"
        $header = @{"accept" = "text/plain"}
        
        $maxRetries = 2
        $retryCount = 0
        $apiSuccess = $false
        
        while ($retryCount -lt $maxRetries -and -not $apiSuccess) {
            try {
                $web = Invoke-WebRequest -Uri $uri -Headers $header -TimeoutSec 15 -ErrorAction Stop
                $db = $web.content | ConvertFrom-Json
                $site = $db | Where-Object { $_.sitecode -eq $storeCode }
                
                if ($site -and $site.storeNumber) {
                    # Set day and time based on even/odd store number
                    if (($site.storeNumber % 2) -eq 0) {
                        $dayOfTheWeek = "Tuesday"  # EVEN
                    } else {
                        $dayOfTheWeek = "Thursday" # ODD
                    }
                    $apiSuccess = $true
                    Write-Verbose "Successfully retrieved store scheduling from API: Store $($site.storeNumber) -> $dayOfTheWeek"
                } else {
                    throw "Store data not found in API response"
                }
            } catch {
                $retryCount++
                if ($retryCount -lt $maxRetries) {
                    Start-Sleep -Seconds 2
                } else {
                    Write-Warning "Failed to contact API after $maxRetries attempts. Using fallback logic. Error: $_"
                }
            }
        }
        
        # Fallback logic based on hostname if API fails
        if (-not $apiSuccess) {
            $storeNumber = [int]$storeCode
            if (($storeNumber % 2) -eq 0) {
                $dayOfTheWeek = "Tuesday"  # EVEN stores
            } else {
                $dayOfTheWeek = "Thursday" # ODD stores  
            }
            Write-Warning "Using hostname-based fallback scheduling: Store $storeNumber -> $dayOfTheWeek"
        }
    } else {
        throw "Unable to extract store code from hostname: $hostname"
    }
} catch {
    Write-Warning "Failed to determine store-specific scheduling. Using default schedule (Tuesday). Error: $_"
    $dayOfTheWeek = "Tuesday"
}

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $dayOfTheWeek -At 4am
$settings = New-ScheduledTaskSettingsSet -WakeToRun
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

#=============================
# Create Check-SCCMHealth Task
#=============================
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCheck"

$desc = "Will create a scheduled task to run based on even/odd store number. Task will run Check-SCCMHealth. Output will be stored locally until retrieved by server."

Register-ScheduledTask -TaskName "Check-SCCMHealthTask" `
                       -Action $action `
                       -Trigger $trigger `
                       -Settings $settings `
                       -Principal $principal `
                       -Description $desc

if(Get-ScheduledTask -TaskName Check-SCCMHealthTask){
    $results += "[+] Created Check-SCCMHealth task"
} else{
    $results += "[!] Failed to create Check-SCCMHealth task"
}

#=============================
# Create Remove-SCCM Task
#=============================
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedRemove -Interactive $false"

$desc = "This task will only run when manually triggered. When run, it will execute a script that removes the SCCM client from the machine."

Register-ScheduledTask -TaskName "Remove-SCCMTask" `
                       -Action $action `
                       -Settings $settings `
                       -Principal $principal `
                       -Description $desc

if(Get-ScheduledTask -TaskName Remove-SCCMTask){
    $results += "[+] Created Remove-SCCM task"
} else{
    $results += "[!] Failed to create Remove-SCCM task"
}

#========================
# Create Reinstall-SCCM Task
#========================
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedReinstall"

$desc = "Will create a scheduled task to run only when triggered. When triggered, will call a script that will reinstall SCCM client on machine."

Register-ScheduledTask -TaskName "Reinstall-SCCMTask" `
                        -Action $action `
                        -Settings $settings `
                        -Principal $principal `
                        -Description $desc

if(Get-ScheduledTask -TaskName Reinstall-SCCMTask){
    $results += "[+] Created Reinstall-SCCM task"
} else{
    $results += "[!] Failed to create Reinstall-SCCM task"
}

# Return all results
return $results -join "; "