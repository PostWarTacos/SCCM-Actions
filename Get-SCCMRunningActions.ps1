<#
.SYNOPSIS
    Checks a target computer for running SCCM task sequences and common SCCM client actions.

.DESCRIPTION
    This script attempts multiple methods to detect whether a Task Sequence or other
    SCCM-related client actions are currently running on a target computer. It
    prefers WinRM/Invoke-Command (if available), falls back to CIM/WMI, and lastly
    attempts remote file reads of common SCCM logs (if admin shares are available).

.PARAMETER ComputerName
    Target computer to query. Defaults to the local computer.

.PARAMETER Credential
    Optional PSCredential to use for remote connections.

.PARAMETER UseCim
    Force using CIM (remoting via CIM) instead of Invoke-Command.

.EXAMPLE
    .\Get-SCCMRunningActions.ps1 -ComputerName CLIENT01

.EXAMPLE
    $cred = Get-Credential
    .\Get-SCCMRunningActions.ps1 -ComputerName CLIENT01 -Credential $cred

.NOTES
    - Requires administrative privileges on the target machine for some checks.
    - Best-effort script: environments may differ. If WinRM is disabled this script
      will try CIM/DCOM and file-share fallbacks.
    - Author: Matthew Wurtz
    - Date: 2025-11-10
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,

    [switch]$UseCim,
    
    [switch]$ShowDetails
)

function New-ResultObject {
    param($Computer)
    return [PSCustomObject]@{
        ComputerName = $Computer
        Timestamp = (Get-Date)
        WinRMAvailable = $false
        RunningTSProcesses = @()
        TaskSequenceDetected = $false
        TaskSequenceName = $null
        TaskSequenceStartTime = $null
        ActiveClientActions = @()
        InstallingItems = @()
        AvailableItems = @()
        FailedItems = @()
        Notes = @()
    }
}

function Test-IsLocalhost {
    param($ComputerName)
    $localNames = @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '.', $env:COMPUTERNAME.ToLower())
    return $localNames -contains $ComputerName.ToLower()
}

function Get-SCCMApplicationStatus {
    param($ShowDebug = $false)
    
    $appStatus = @{
        Installing = @()
        Available = @()
        Failed = @()
    }
    
    try {
        # Get application deployment status
        $applications = Get-CimInstance -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_Application -ErrorAction SilentlyContinue
        
        if ($applications) {
            foreach ($app in $applications) {
                $appInfo = [PSCustomObject]@{
                    Name = $app.Name
                    Version = $app.SoftwareVersion
                    Publisher = $app.Publisher
                    InstallState = $app.InstallState
                    EvaluationState = $app.EvaluationState
                    ErrorCode = $app.ErrorCode
                    LastEvalTime = $app.LastEvalTime
                    Type = "Application"
                }
                
                # Categorize based on state - be more aggressive about detecting failures
                # Also check evaluation states that indicate problems
                $hasFailureCondition = ($app.ErrorCode -and $app.ErrorCode -ne 0) -or 
                                     ($app.EvaluationState -eq 4) -or  # EvaluationState 4 = InstallFailed
                                     ($app.EvaluationState -eq 7) -or  # EvaluationState 7 = Error
                                     ($app.EvaluationState -eq 8)      # EvaluationState 8 = Reboot pending from failure
                
                switch ($app.InstallState) {
                    "Installing" { $appStatus.Installing += $appInfo }
                    "Available" { 
                        if ($hasFailureCondition) {
                            $appStatus.Failed += $appInfo
                        } else {
                            $appStatus.Available += $appInfo 
                        }
                    }
                    "InstallFailed" { $appStatus.Failed += $appInfo }
                    "Failed" { $appStatus.Failed += $appInfo }
                    "Error" { $appStatus.Failed += $appInfo }
                    "NotInstalled" { 
                        if ($app.EvaluationState -eq 1) { 
                            $appStatus.Installing += $appInfo 
                        } elseif ($hasFailureCondition) {
                            $appStatus.Failed += $appInfo
                        } else { 
                            $appStatus.Available += $appInfo 
                        }
                    }
                    "Installed" { 
                        # Only show if there was a recent failure or it's part of ongoing deployment
                        if ($hasFailureCondition) {
                            $appStatus.Failed += $appInfo
                        }
                    }
                    default {
                        # Catch any other states that might indicate failure
                        if ($hasFailureCondition) {
                            $appStatus.Failed += $appInfo
                        } else {
                            $appStatus.Available += $appInfo
                        }
                    }
                }
            }
        }
        
        # Get task sequence information from WMI
        $taskSequences = Get-CimInstance -Namespace "ROOT\ccm\Policy\Machine\ActualConfig" -ClassName CCM_TaskSequence -ErrorAction SilentlyContinue
        if ($taskSequences) {
            foreach ($ts in $taskSequences) {
                # Check for task sequence execution history to detect failures
                $tsStatus = "Available"
                $errorCode = 0
                
                try {
                    # Check execution history from ClientSDK
                    $executionHistory = Get-CimInstance -Namespace "ROOT\ccm\SoftMgmtAgent" -ClassName "CCM_ExecutionHistory" -Filter "PackageID='$($ts.PKG_PackageID)'" -ErrorAction SilentlyContinue
                    if ($executionHistory) {
                        $lastExecution = $executionHistory | Sort-Object ExecutionTime -Descending | Select-Object -First 1
                        if ($lastExecution.ExecutionState -eq 'Error' -or $lastExecution.ExecutionState -eq 'Failed' -or $lastExecution.ExitCode -ne 0) {
                            $tsStatus = "Failed"
                            $errorCode = $lastExecution.ExitCode
                        }
                    }
                } catch {
                    # Fallback - check if Software Center shows it as failed (based on common failure patterns)
                    $tsName = $ts.PKG_Name
                    if ($tsName -match "(Admin Change|Tenable Agent|BranchCache)" -and $ShowDebug) {
                        Write-Host "    Checking $tsName for failure indicators..." -ForegroundColor Gray
                    }
                }
                
                $tsInfo = [PSCustomObject]@{
                    Name = $ts.PKG_Name
                    Version = $ts.PKG_Version
                    Publisher = "Microsoft SCCM"
                    InstallState = $tsStatus
                    EvaluationState = 0
                    ErrorCode = $errorCode
                    LastEvalTime = $null
                    Type = "Task Sequence"
                }
                
                if ($tsStatus -eq "Failed") {
                    $appStatus.Failed += $tsInfo
                } else {
                    $appStatus.Available += $tsInfo
                }
            }
        }
        
        # Check Software Center deployment states for more accurate failure detection
        try {
            # Check Task Sequence execution requests for failures
            $tsExecutionRequests = Get-CimInstance -Namespace "ROOT\ccm\SoftMgmtAgent" -ClassName "CCM_TSExecutionRequest" -ErrorAction SilentlyContinue
            foreach ($tsReq in $tsExecutionRequests) {
                if ($tsReq.CompletionState -eq "Failure") {
                    # Try to find the corresponding task sequence name
                    $tsName = "Unknown Task Sequence"
                    $tsPolicy = $taskSequences | Where-Object { $_.ADV_AdvertisementID -eq $tsReq.AdvertID }
                    if ($tsPolicy) {
                        $tsName = $tsPolicy.PKG_Name
                    } else {
                        # Fallback - check if we can match by advertisement ID pattern
                        $tsName = "Task Sequence (ID: $($tsReq.AdvertID))"
                    }
                    
                    $failedItem = [PSCustomObject]@{
                        Name = $tsName
                        Version = ""
                        Publisher = "Microsoft SCCM"
                        InstallState = "Failed"
                        EvaluationState = 0
                        ErrorCode = if ($tsReq.ProgramExitCode) { $tsReq.ProgramExitCode } else { 1 }
                        LastEvalTime = $tsReq.ReceivedTime
                        Type = "Task Sequence"
                    }
                    $appStatus.Failed += $failedItem
                    
                    if ($ShowDebug) {
                        Write-Host "    Found failed TS execution: $tsName (AdvertID: $($tsReq.AdvertID))" -ForegroundColor Red
                    }
                }
            }
        } catch {
            if ($ShowDebug) {
                Write-Host "  Could not check TS execution requests for failures" -ForegroundColor Yellow
            }
        }

        # Check recent application installation history for failures
        # Look back further to account for 360+ minute installation timeouts
        try {
            $appEnforceLog = Join-Path $env:windir 'ccm\logs\AppEnforce.log'
            if (Test-Path $appEnforceLog) {
                $recentFailures = Get-Content $appEnforceLog -Tail 1000 -ErrorAction SilentlyContinue | 
                    Where-Object { $_ -match 'failed|error' -and $_ -match 'exit code' } |
                    ForEach-Object {
                        if ($_ -match 'App DT "([^"]+)".*exit code (\d+)') {
                            [PSCustomObject]@{
                                Name = $matches[1]
                                Version = "Unknown"
                                Publisher = "Unknown"
                                InstallState = "InstallFailed"
                                EvaluationState = 0
                                ErrorCode = $matches[2]
                                LastEvalTime = (Get-Date)
                                Type = "Application"
                            }
                        }
                    } | Select-Object -Last 5
                
                if ($recentFailures) {
                    $appStatus.Failed += $recentFailures
                }
            }
        } catch {
            if ($ShowDebug) {
                Write-Host "  Warning: Could not read AppEnforce.log for failure details" -ForegroundColor Yellow
            }
        }
        
        if ($ShowDebug) {
            Write-Host "  Application Status Summary:" -ForegroundColor Gray
            Write-Host "    Installing: $($appStatus.Installing.Count)" -ForegroundColor Gray
            Write-Host "    Available: $($appStatus.Available.Count)" -ForegroundColor Gray
            Write-Host "    Failed: $($appStatus.Failed.Count)" -ForegroundColor Gray
        }
        
        return $appStatus
        
    } catch {
        if ($ShowDebug) {
            Write-Host "  Error getting application status: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $appStatus
    }
}

function Get-TaskSequenceInfo {
    param($IsLocal, $ShowDebug = $false)
    
    $tsInfo = @{
        Name = $null
        StartTime = $null
        IsRunning = $false
        EnvironmentVars = @()
        LogActivity = $false
    }
    
    try {
        if ($IsLocal) {
            # Check for TS environment variables (only exist during TS execution)
            $tsEnvVars = @('_SMSTSPackageName', '_SMSTSAdvertID', '_SMSTSLogPath', '_SMSTSCurrentActionName', '_SMSTSProgramName')
            foreach ($envVar in $tsEnvVars) {
                $value = [Environment]::GetEnvironmentVariable($envVar)
                if ($value) {
                    $tsInfo.EnvironmentVars += "$envVar = $value"
                    if ($envVar -eq '_SMSTSPackageName' -or $envVar -eq '_SMSTSProgramName') {
                        $tsInfo.Name = $value
                        $tsInfo.IsRunning = $true
                    }
                }
            }
            
            # Check for active Software Center installations
            try {
                # Check for active applications/task sequences via WMI
                $activeJobs = Get-CimInstance -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_Application -ErrorAction SilentlyContinue
                if ($activeJobs) {
                    $installingApps = $activeJobs | Where-Object { $_.InstallState -eq "Installing" -or $_.EvaluationState -eq 1 }
                    if ($installingApps) {
                        if ($ShowDebug) {
                            Write-Host "  Found $($installingApps.Count) installing applications" -ForegroundColor Gray
                            $installingApps | ForEach-Object { Write-Host "    - $($_.Name) (State: $($_.InstallState))" -ForegroundColor Gray }
                        }
                        # Check if any look like task sequences
                        $installingTS = $installingApps | Where-Object { $_.Name -match "TS|Task Sequence" }
                        if ($installingTS -and -not $tsInfo.IsRunning) {
                            $tsInfo.IsRunning = $true
                            if (-not $tsInfo.Name) {
                                $tsInfo.Name = $installingTS[0].Name
                                if ($ShowDebug) {
                                    Write-Host "  Found running TS from active applications: $($tsInfo.Name)" -ForegroundColor Gray
                                }
                            }
                        }
                    }
                }
                
                # Check for running task sequence via WMI policies (only for available list, not for running detection)
                $tsJob = Get-CimInstance -Namespace "ROOT\ccm\Policy\Machine\ActualConfig" -ClassName CCM_TaskSequence -ErrorAction SilentlyContinue
                if ($tsJob) {
                    if ($ShowDebug) {
                        Write-Host "  Found CCM_TaskSequence policy objects: $($tsJob.Count)" -ForegroundColor Gray
                    }
                    # Look for task sequences with recent activity
                    $sortedTS = $tsJob | Sort-Object PKG_Name
                    if ($ShowDebug) {
                        Write-Host "  Available Task Sequences:" -ForegroundColor Gray
                        $sortedTS | ForEach-Object { Write-Host "    - $($_.PKG_Name)" -ForegroundColor Gray }
                    }
                    
                    # Store TS list for available items (don't override active TS name)
                    $tsInfo.AvailableTaskSequences = $sortedTS
                }
            } catch {
                if ($ShowDebug) {
                    Write-Host "  WMI query failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            
            if ($ShowDebug -and $tsInfo.EnvironmentVars.Count -gt 0) {
                Write-Host "  TS Environment Variables found:" -ForegroundColor Gray
                $tsInfo.EnvironmentVars | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            }
            
            # Check smsts.log for current activity
            $smstsPath = Join-Path $env:windir 'ccm\logs\smsts.log'
            if (Test-Path $smstsPath) {
                $fileInfo = Get-Item $smstsPath
                $timeDiff = (Get-Date) - $fileInfo.LastWriteTime
                
                if ($ShowDebug) {
                    Write-Host "  smsts.log found - Last modified: $($fileInfo.LastWriteTime) ($([math]::Round($timeDiff.TotalMinutes, 1)) minutes ago)" -ForegroundColor Gray
                }
                
                # If log was modified recently, consider it active (expand window for longer-running TS)
                # Also consider active if we detect TS processes running
                $hasActiveProcesses = Get-CimInstance -ClassName Win32_Process | Where-Object { 
                    @('tsmanager.exe', 'smsts.exe', 'tsprogressui.exe') -contains $_.Name.ToLower() 
                } | Measure-Object | Select-Object -ExpandProperty Count
                
                # Account for SCCM default timeout of 360 minutes (6 hours), allow extra for custom timeouts
                $timeWindow = if ($hasActiveProcesses -gt 0) { 480 } else { 360 }  # 8 hours if TS processes found, 6 hours otherwise
                
                if ($timeDiff.TotalMinutes -le $timeWindow) {
                    $tsInfo.LogActivity = $true
                    $tsInfo.IsRunning = $true
                    
                    # Read more of the log to find TS name and start time
                    $logContent = Get-Content $smstsPath -ErrorAction SilentlyContinue
                    
                    # Look for TS start time from the most recent TSManager initialization
                    if (-not $tsInfo.StartTime) {
                        $tsInitLines = $logContent | Where-Object { $_ -match "TSManager initialized environment for task sequence" }
                        if ($tsInitLines) {
                            # Get the most recent one, preferably from today
                            $todayLines = $tsInitLines | Where-Object { $_ -match "date=`"$today`"" }
                            $targetLine = if ($todayLines) { $todayLines | Select-Object -Last 1 } else { $tsInitLines | Select-Object -Last 1 }
                            
                            if ($targetLine -match 'time="([^"]+)"\s+date="([^"]+)"') {
                                try {
                                    $timeStr = $matches[1]
                                    $dateStr = $matches[2]
                                    # Parse the time (format: HH:mm:ss.fff+offset)
                                    $timePart = ($timeStr -split '\+')[0]  # Remove timezone offset
                                    $fullDateTime = "$dateStr $timePart"
                                    $tsInfo.StartTime = [DateTime]::ParseExact($fullDateTime, "MM-dd-yyyy HH:mm:ss.fff", $null)
                                    if ($ShowDebug) {
                                        Write-Host "  Found TS start time from recent init: $($tsInfo.StartTime)" -ForegroundColor Gray
                                    }
                                } catch {
                                    if ($ShowDebug) {
                                        Write-Host "  Error parsing start time from recent init: $($_.Exception.Message)" -ForegroundColor Yellow
                                    }
                                }
                            }
                        }
                        
                        # Fallback: look for any TSManager activity from today
                        if (-not $tsInfo.StartTime) {
                            $todayActivity = $logContent | Where-Object { $_ -match "TSManager.*date=`"$today`"" } | Select-Object -First 1
                            if ($todayActivity -and $todayActivity -match 'time="([^"]+)"\s+date="([^"]+)"') {
                                try {
                                    $timeStr = $matches[1]
                                    $dateStr = $matches[2]
                                    $timePart = ($timeStr -split '\+')[0]
                                    $fullDateTime = "$dateStr $timePart"
                                    $tsInfo.StartTime = [DateTime]::ParseExact($fullDateTime, "MM-dd-yyyy HH:mm:ss.fff", $null)
                                    if ($ShowDebug) {
                                        Write-Host "  Found TS start time from today's activity: $($tsInfo.StartTime)" -ForegroundColor Gray
                                    }
                                } catch {
                                    # Continue if this fails
                                }
                            }
                        }
                    }
                    
                    # Look for TS name - prioritize most recent entries from today
                    $today = (Get-Date).ToString("MM-dd-yyyy")
                    
                    # Pattern 1: TSManager initialized environment (most reliable for current TS)
                    # Search the entire log content for this pattern
                    $tsInitLines = $logContent | Where-Object { $_ -match "TSManager initialized environment for task sequence.*Name = '([^']+)'" }
                    if ($tsInitLines) {
                        # Get the most recent one, preferably from today
                        $todayLines = $tsInitLines | Where-Object { $_ -match "date=`"$today`"" }
                        $targetLine = if ($todayLines) { 
                            $todayLines | Select-Object -Last 1 
                        } else { 
                            $tsInitLines | Select-Object -Last 1 
                        }
                        
                        if ($ShowDebug) {
                            Write-Host "  Found $($tsInitLines.Count) TSManager init lines, $($todayLines.Count) from today" -ForegroundColor Gray
                            if ($targetLine) {
                                Write-Host "  Using line: $($targetLine.Substring(0, [Math]::Min(100, $targetLine.Length)))..." -ForegroundColor Gray
                            }
                        }
                        
                        if ($targetLine -match "Name = '([^']+)'") {
                            $tsInfo.Name = $matches[1].Trim()
                            if ($ShowDebug) {
                                Write-Host "  Found TS name (TSManager Init): $($tsInfo.Name)" -ForegroundColor Gray
                                if ($targetLine -match "date=`"([^`"]+)`"") {
                                    Write-Host "  TS initialized on: $($matches[1])" -ForegroundColor Gray
                                }
                            }
                        }
                    }
                    
                    # Fallback patterns if TSManager init not found
                    if (-not $tsInfo.Name) {
                        foreach ($line in $recentContent) {
                            # Pattern 2: Package name
                            if ($line -match 'Package Name = "([^"]+)"' -and -not $tsInfo.Name) {
                                $tsInfo.Name = $matches[1].Trim()
                                if ($ShowDebug) {
                                    Write-Host "  Found TS name (Package): $($tsInfo.Name)" -ForegroundColor Gray
                                }
                                break
                            }
                            # Pattern 3: Task sequence deployment
                            elseif ($line -match 'Task sequence deployment ([A-Z0-9]{8}):([^:]+)' -and -not $tsInfo.Name) {
                                $tsInfo.Name = $matches[2].Trim()
                                if ($ShowDebug) {
                                    Write-Host "  Found TS name (Deployment): $($tsInfo.Name)" -ForegroundColor Gray
                                }
                                break
                            }
                        }
                    }
                    
                    if ($ShowDebug) {
                        Write-Host "  Recent log activity detected - TS likely running" -ForegroundColor Gray
                        Write-Host "  Final TS Name: '$($tsInfo.Name)'" -ForegroundColor Gray
                        Write-Host "  Final TS Start Time: '$($tsInfo.StartTime)'" -ForegroundColor Gray
                    }
                }
            } elseif ($ShowDebug) {
                Write-Host "  smsts.log not found at $smstsPath" -ForegroundColor Gray
            }
        }
        
        return $tsInfo
    } catch {
        if ($ShowDebug) {
            Write-Host "  Error in Get-TaskSequenceInfo: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $tsInfo
    }
}

$result = New-ResultObject -Computer $ComputerName
$isLocalhost = Test-IsLocalhost -ComputerName $ComputerName

Write-Host "Checking $ComputerName for SCCM/Task Sequence activity..." -ForegroundColor Cyan

# Known process indicators for Task Sequences / client actions
$tsProcesses = @(
    'smsts.exe',           # Task Sequence Engine - PRIMARY INDICATOR
    'tsprogressui.exe',    # Task Sequence Progress UI
    'smstasksequence.exe', # Task Sequence executable
    'tsmbootstrap.exe',    # Task Sequence Bootstrap
    'tsmanager.exe',       # Task Sequence Manager
    'osdmgr.exe'           # Operating System Deployment Manager
    # Note: Removed ccmexec, msiexec, ccmsetup as they don't necessarily indicate TS activity
)

function Test-WinRM {
    param($Computer, $Cred)
    try {
        $s = New-PSSession -ComputerName $Computer -Credential $Cred -ErrorAction Stop
        Remove-PSSession $s
        return $true
    } catch {
        return $false
    }
}

function Invoke-RemoteCheck {
    param($Computer, $Cred)

    $script = {
        param($tsProcs)
        $out = [ordered]@{}
        $out.Processes = Get-Process | Select-Object -Property Name,Id,Path,StartTime -ErrorAction SilentlyContinue
        $out.Services = Get-Service -Name ccmexec -ErrorAction SilentlyContinue | Select-Object Name,Status
        $logInfo = @{}
        $smstsPath = Join-Path $env:windir 'ccm\logs\smsts.log'
        $execmgrPath = Join-Path $env:windir 'ccm\logs\execmgr.log'
        if (Test-Path $smstsPath) {
            $fi = Get-Item $smstsPath
            $logInfo.smsts = @{ Path = $smstsPath; LastWrite = $fi.LastWriteTime; Length = $fi.Length }
        }
        if (Test-Path $execmgrPath) {
            $fi2 = Get-Item $execmgrPath
            $logInfo.execmgr = @{ Path = $execmgrPath; LastWrite = $fi2.LastWriteTime; Length = $fi2.Length }
            # read last 50 lines for hints
            try { $logInfo.execmgrTail = Get-Content $execmgrPath -Tail 50 -ErrorAction SilentlyContinue } catch { $logInfo.execmgrTail = $null }
        }
        $out.Logs = $logInfo
        # detect probable task sequence by process name
        $found = $out.Processes | Where-Object { $tsProcs -contains ($_.Name.ToLower()) }
        $out.TaskSequenceDetected = ($null -ne $found -and $found.Count -gt 0)
        
        # Also check for recent log activity if smsts.log exists
        if (-not $out.TaskSequenceDetected -and $logInfo.smsts) {
            # Check if smsts.log was modified within the timeout window (360+ minutes)
            $recentActivity = (Get-Date).AddMinutes(-360)
            if ($logInfo.smsts.LastWrite -gt $recentActivity) {
                $out.TaskSequenceDetected = $true
            }
        }
        
        return $out
    }

    try {
        if ($Cred) {
            $res = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock $script -ArgumentList ($tsProcesses) -ErrorAction Stop
        } else {
            $res = Invoke-Command -ComputerName $Computer -ScriptBlock $script -ArgumentList ($tsProcesses) -ErrorAction Stop
        }
        return $res
    } catch {
        throw $_
    }
}

function Cim-RemoteCheck {
    param($Computer, $Cred)
    $ops = [ordered]@{}
    try {
        if ($Cred) {
            $session = New-CimSession -ComputerName $Computer -Credential $Cred -ErrorAction Stop
        } else {
            $session = New-CimSession -ComputerName $Computer -ErrorAction Stop
        }
    } catch {
        throw $_
    }

    # Processes
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -CimSession $session | Select-Object Name,ProcessId,CommandLine,CreationDate
        $ops.Processes = $procs
    } catch {
        $ops.Processes = @()
    }

    # Service status for ccmexec
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='ccmexec'" -CimSession $session
        if ($svc) { $ops.Services = $svc | Select-Object Name,State } else { $ops.Services = $null }
    } catch { $ops.Services = $null }

    # Try reading last write of smsts.log and execmgr.log if present via remote path
    $remoteSmsts = "\\$Computer\c$\Windows\ccm\logs\smsts.log"
    $remoteExec = "\\$Computer\c$\Windows\ccm\logs\execmgr.log"
    $logInfo = @{}
    try { if (Test-Path $remoteSmsts) { $fi = Get-Item $remoteSmsts; $logInfo.smsts = @{ Path=$remoteSmsts; LastWrite=$fi.LastWriteTime; Length=$fi.Length } } } catch {}
    try { if (Test-Path $remoteExec) { $fi2 = Get-Item $remoteExec; $logInfo.execmgr = @{ Path=$remoteExec; LastWrite=$fi2.LastWriteTime; Length=$fi2.Length }; $logInfo.execmgrTail = Get-Content $remoteExec -Tail 50 -ErrorAction SilentlyContinue } } catch {}
    $ops.Logs = $logInfo

    # Detect probable TS
    $found = @()
    if ($ops.Processes) {
        foreach ($p in $ops.Processes) {
            if ($tsProcesses -contains $p.Name.ToLower()) { $found += $p }
        }
    }
    $ops.TaskSequenceDetected = ($found.Count -gt 0)
    
    # Also check for recent log activity if smsts.log exists
    if (-not $ops.TaskSequenceDetected -and $logInfo.smsts) {
        # Check if smsts.log was modified within the timeout window (360+ minutes)
        $recentActivity = (Get-Date).AddMinutes(-360)
        if ($logInfo.smsts.LastWrite -gt $recentActivity) {
            $ops.TaskSequenceDetected = $true
        }
    }

    if ($session) { $session | Remove-CimSession }
    return $ops
}

# Get task sequence info first
$tsInfo = Get-TaskSequenceInfo -IsLocal $isLocalhost -ShowDebug $ShowDetails
$result.TaskSequenceDetected = $tsInfo.IsRunning
$result.TaskSequenceName = $tsInfo.Name
$result.TaskSequenceStartTime = $tsInfo.StartTime

# Get application and deployment status
$appStatus = Get-SCCMApplicationStatus -ShowDebug $ShowDetails
$result.InstallingItems = $appStatus.Installing
$result.AvailableItems = $appStatus.Available
$result.FailedItems = $appStatus.Failed

if ($ShowDetails) {
    Write-Host "  Is localhost: $isLocalhost" -ForegroundColor Gray
    Write-Host "  TS Info - Running: $($tsInfo.IsRunning), Name: $($tsInfo.Name)" -ForegroundColor Gray
    Write-Host "  TS Info - Log Activity: $($tsInfo.LogActivity), Env Vars: $($tsInfo.EnvironmentVars.Count)" -ForegroundColor Gray
}

# Main flow: skip remote calls for localhost, try WinRM unless forced to use CIM
if (-not $isLocalhost -and -not $UseCim) {
    try {
        $winrm = Test-WinRM -Computer $ComputerName -Cred $Credential
        $result.WinRMAvailable = $winrm
    } catch { $result.Notes += "WinRM test failed: $($_.Exception.Message)" }
}

if ($isLocalhost) {
    # For localhost, check processes locally across ALL user sessions
    if ($ShowDetails) { Write-Host "  Using local process check (all sessions)..." -ForegroundColor Gray }
    try {
        # Use WMI to get ALL processes across all user sessions
        $localProcesses = Get-CimInstance -ClassName Win32_Process | Select-Object Name,ProcessId,CommandLine,CreationDate,SessionId -ErrorAction SilentlyContinue
        
        if ($ShowDetails) {
            Write-Host "  Looking for TS processes: $($tsProcesses -join ', ')" -ForegroundColor Gray
            Write-Host "  Total processes found: $($localProcesses.Count)" -ForegroundColor Gray
            
            # Show all potentially SCCM-related processes
            $potentialProcesses = $localProcesses | Where-Object { $_.Name -match '(smsts|ccm|ts|sccm|osd)' }
            if ($potentialProcesses) {
                Write-Host "  All SCCM-related processes found:" -ForegroundColor Gray
                $potentialProcesses | ForEach-Object { 
                    $isMatch = $tsProcesses -contains $_.Name.ToLower()
                    $matchIndicator = if ($isMatch) { "[MATCH]" } else { "      " }
                    Write-Host "    $matchIndicator $($_.Name) (Session: $($_.SessionId), PID: $($_.ProcessId))" -ForegroundColor Gray 
                }
            } else {
                Write-Host "  No SCCM-related processes found" -ForegroundColor Gray
            }
        }
        
        $result.RunningTSProcesses = $localProcesses | Where-Object { 
            $tsProcesses -contains $_.Name.ToLower()
        } | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                ProcessId = $_.ProcessId
                SessionId = $_.SessionId
                CommandLine = $_.CommandLine
            }
        }
        
        if ($ShowDetails) { 
            $processCount = if ($result.RunningTSProcesses) { @($result.RunningTSProcesses).Count } else { 0 }
            Write-Host "  Found $processCount actual TS processes locally (all sessions)" -ForegroundColor Gray 
        }
        
        # If we found TS processes, update the detection and try to get the name from logs
        if ($result.RunningTSProcesses -and @($result.RunningTSProcesses).Count -gt 0) {
            $result.TaskSequenceDetected = $true
            
            # If we have TS processes but no name, try to get it from logs with expanded search
            if (-not $result.TaskSequenceName) {
                $expandedTSInfo = Get-TaskSequenceInfo -IsLocal $true -ShowDebug $false
                if ($expandedTSInfo.Name) {
                    $result.TaskSequenceName = $expandedTSInfo.Name
                    $result.TaskSequenceStartTime = $expandedTSInfo.StartTime
                    if ($ShowDetails) {
                        Write-Host "  Updated TS name from logs: $($expandedTSInfo.Name)" -ForegroundColor Gray
                    }
                }
            }
        }
        
    } catch {
        $result.Notes += "Local process check failed: $($_.Exception.Message)"
        if ($ShowDetails) { Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red }
    }
} elseif ($result.WinRMAvailable -and -not $UseCim) {
    try {
        if ($ShowDetails) { Write-Host "  Using WinRM/Invoke-Command method..." -ForegroundColor Gray }
        $remote = Invoke-RemoteCheck -Computer $ComputerName -Cred $Credential
        
        if ($ShowDetails) { 
            Write-Host "  Found $($remote.Processes.Count) total processes" -ForegroundColor Gray 
            Write-Host "  Looking for processes: $($tsProcesses -join ', ')" -ForegroundColor Gray
        }
        
        # Only collect SCCM-related processes
        $result.RunningTSProcesses = $remote.Processes | Where-Object { $tsProcesses -contains ($_.Name.ToLower()) } | ForEach-Object { ($_ | Select-Object Name,Id) }
        $result.TaskSequenceDetected = $remote.TaskSequenceDetected
        
        if ($ShowDetails) { 
            $processCount = @($result.RunningTSProcesses).Count
            Write-Host "  Found $processCount SCCM processes" -ForegroundColor Gray 
            Write-Host "  Remote TaskSequenceDetected: $($remote.TaskSequenceDetected)" -ForegroundColor Gray
        }
        
        if ($remote.Logs.execmgr) { $result.ActiveClientActions += ($remote.Logs.execmgrTail | Select-String -Pattern 'Starting|Started|Action' -SimpleMatch | Select-Object -Unique -ExpandProperty Line) }
    } catch {
        $result.Notes += "Invoke-Command failed: $($_.Exception.Message)"
        if ($ShowDetails) { Write-Host "  WinRM failed, will try CIM fallback" -ForegroundColor Yellow }
        # fall through to CIM
    }
}

if ((-not $result.TaskSequenceDetected) -and -not $isLocalhost -and ($result.WinRMAvailable -eq $false -or $null -ne $result.Notes -and $result.Notes.Count -gt 0 -or $UseCim)) {
    # Try CIM fallback
    try {
        if ($ShowDetails) { Write-Host "  Using CIM fallback method..." -ForegroundColor Gray }
        $c = Cim-RemoteCheck -Computer $ComputerName -Cred $Credential
        
        if ($ShowDetails) { 
            Write-Host "  Found $($c.Processes.Count) total processes via CIM" -ForegroundColor Gray 
        }
        
        # Only collect SCCM-related processes
        $allProcesses = $c.Processes | ForEach-Object { 
            ($_ | Select-Object @{Name='Name';Expression={$_.Name}}, @{Name='ProcessId';Expression={$_.ProcessId}}) 
        }
        $result.RunningTSProcesses = $allProcesses | Where-Object { $tsProcesses -contains ($_.Name.ToLower()) }
        $result.TaskSequenceDetected = $c.TaskSequenceDetected
        
        if ($ShowDetails) { 
            $processCount = @($result.RunningTSProcesses).Count
            Write-Host "  Found $processCount SCCM processes via CIM" -ForegroundColor Gray 
            Write-Host "  CIM TaskSequenceDetected: $($c.TaskSequenceDetected)" -ForegroundColor Gray
        }
        
        if ($c.Logs.execmgrTail) { $result.ActiveClientActions += ($c.Logs.execmgrTail | Select-String -Pattern 'Starting|Started|Action' -SimpleMatch | Select-Object -Unique -ExpandProperty Line) }
    } catch {
        $result.Notes += "CIM fallback failed: $($_.Exception.Message)"
        if ($ShowDetails) { Write-Host "  CIM fallback failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# Final heuristic: examine detected processes for likely TS
if (-not $result.TaskSequenceDetected -and $result.RunningTSProcesses) {
    $result.TaskSequenceDetected = ($result.RunningTSProcesses.Count -gt 0)
    if ($ShowDetails) { 
        $processCount = @($result.RunningTSProcesses).Count
        Write-Host "  Final heuristic - RunningTSProcesses count: $processCount" -ForegroundColor Gray 
    }
}

if ($ShowDetails) { 
    Write-Host "  Final TaskSequenceDetected: $($result.TaskSequenceDetected)" -ForegroundColor Gray 
    if ($result.RunningTSProcesses) {
        $processes = @($result.RunningTSProcesses)
        if ($processes.Count -gt 0) {
            Write-Host "  Detected SCCM processes:" -ForegroundColor Gray
            $processes | ForEach-Object { 
                $processId = $_.ProcessId -or $_.Id
                Write-Host "    - $($_.Name) (PID: $processId)" -ForegroundColor Gray 
            }
        }
    } else {
        Write-Host "  No TS processes detected" -ForegroundColor Gray
    }
}

# Output - Show SCCM status in three sections: Installing, Available, Failed
Write-Host "`nSCCM Status for ${ComputerName}:" -ForegroundColor Green

# ========================================
# INSTALLING SECTION
# ========================================
$hasInstalling = $false

# Check for running task sequence
if ($result.TaskSequenceDetected) {
    if (-not $hasInstalling) {
        Write-Host "`n  [INSTALLING]" -ForegroundColor Red
        $hasInstalling = $true
    }
    
    $displayName = if ($result.TaskSequenceName) { $result.TaskSequenceName } else { "Unknown Task Sequence" }
    Write-Host "    Task Sequence: $displayName" -ForegroundColor Yellow
    if ($result.TaskSequenceStartTime) {
        Write-Host "      Started: $($result.TaskSequenceStartTime)" -ForegroundColor White
    }
    
    # Show only the SCCM-related processes that are running
    if ($result.RunningTSProcesses) {
        $processes = @($result.RunningTSProcesses)
        $processes | ForEach-Object { 
            $processId = if ($_.ProcessId) { $_.ProcessId } elseif ($_.Id) { $_.Id } else { "Unknown" }
            $sessionInfo = if ($_.SessionId -ne $null) { " Session: $($_.SessionId)" } else { "" }
            Write-Host "      Process: $($_.Name) (PID: $processId$sessionInfo)" -ForegroundColor White
        }
    }
}

        # Show installing applications
if ($result.InstallingItems.Count -gt 0) {
    if (-not $hasInstalling) {
        Write-Host "`n  [INSTALLING]" -ForegroundColor Red
        $hasInstalling = $true
    }
    
    $result.InstallingItems | ForEach-Object {
        if ($_.Type -eq "Task Sequence" -and $result.TaskSequenceDetected) {
            # Skip - already shown above
        } else {
            Write-Host "    $($_.Type): $($_.Name)" -ForegroundColor Yellow
            if ($_.Version) {
                Write-Host "      Version: $($_.Version)" -ForegroundColor White
            }
            
            # Try to find start time from multiple sources
            $startTime = $null
            $logTime = $null
            
            # First try: Use LastEvalTime if it's within the installation timeout window
            # Default SCCM timeout is 360 minutes (6 hours), but could be longer
            if ($_.LastEvalTime) {
                $evalTime = [DateTime]$_.LastEvalTime
                $timeDiff = (Get-Date) - $evalTime
                if ($timeDiff.TotalHours -le 8) {  # Allow up to 8 hours for custom timeouts
                    $startTime = $evalTime
                }
            }
            
            # Second try: Check AppEnforce.log for installation start
            try {
                $appEnforceLog = Join-Path $env:windir 'ccm\logs\AppEnforce.log'
                if (Test-Path $appEnforceLog) {
                    # Read much more of the log to account for 360+ minute timeout
                    $recentLines = Get-Content $appEnforceLog -Tail 2000 -ErrorAction SilentlyContinue
                    $appName = $_.Name
                    
                    # Look for installation start patterns with various name formats
                    $startPattern = $recentLines | Where-Object { 
                        ($_ -match [regex]::Escape($appName) -or $_ -match $appName.Split('-')[0]) -and 
                        ($_ -match "Starting Install enforcement|Installing|Begin" -or $_ -match "State change.*to.*Installing")
                    } | Select-Object -Last 1
                    
                    if ($startPattern -and $startPattern -match '<time="([^"]+)".*date="([^"]+)"') {
                        try {
                            $timeStr = $matches[1].Split('.')[0]  # Remove milliseconds
                            $dateStr = $matches[2]
                            $fullDateTime = [DateTime]::ParseExact("$dateStr $timeStr", "MM-dd-yyyy HH:mm:ss", $null)
                            $logTime = $fullDateTime
                        } catch {
                            # If parsing fails, continue
                        }
                    }
                }
            } catch {
                # Silently continue if we can't read the log
            }
            
            # Use the more recent time between LastEvalTime and log time
            if ($logTime -and $startTime) {
                $startTime = if ($logTime -gt $startTime) { $logTime } else { $startTime }
            } elseif ($logTime) {
                $startTime = $logTime
            }
            
            # Display start time if found
            if ($startTime) {
                Write-Host "      Started: $($startTime.ToString('MM/dd/yyyy HH:mm:ss'))" -ForegroundColor White
            }
        }
    }
}if (-not $hasInstalling) {
    Write-Host "`n  [INSTALLING]" -ForegroundColor Green
    Write-Host "    No installations in progress" -ForegroundColor Gray
}

# ========================================
# AVAILABLE SECTION
# ========================================
Write-Host "`n  [AVAILABLE]" -ForegroundColor Cyan
if ($result.AvailableItems.Count -gt 0) {
    # Group by type
    $availableApps = $result.AvailableItems | Where-Object { $_.Type -eq "Application" }
    $availableTS = $result.AvailableItems | Where-Object { $_.Type -eq "Task Sequence" }
    
    if ($availableApps.Count -gt 0) {
        Write-Host "    Applications ($($availableApps.Count)):" -ForegroundColor Yellow
        $availableApps | Select-Object -First 10 | ForEach-Object {
            Write-Host "      - $($_.Name)" -ForegroundColor White
        }
        if ($availableApps.Count -gt 10) {
            Write-Host "      ... and $($availableApps.Count - 10) more applications" -ForegroundColor Gray
        }
    }
    
    if ($availableTS.Count -gt 0) {
        Write-Host "    Task Sequences ($($availableTS.Count)):" -ForegroundColor Yellow
        $availableTS | ForEach-Object {
            Write-Host "      - $($_.Name)" -ForegroundColor White
        }
    }
} else {
    Write-Host "    No available deployments" -ForegroundColor Gray
}

# ========================================
# FAILED SECTION
# ========================================
Write-Host "`n  [FAILED]" -ForegroundColor Red
if ($result.FailedItems.Count -gt 0) {
    $result.FailedItems | ForEach-Object {
        Write-Host "    $($_.Type): $($_.Name)" -ForegroundColor Yellow
        if ($_.ErrorCode -and $_.ErrorCode -ne 0) {
            Write-Host "      Error Code: $($_.ErrorCode)" -ForegroundColor White
        }
        if ($_.LastEvalTime) {
            Write-Host "      Failed: $($_.LastEvalTime)" -ForegroundColor White
        }
    }
} else {
    Write-Host "    No recent failures" -ForegroundColor Gray
}

# Show active client actions (filtered for actual running actions)
if ($result.ActiveClientActions.Count -gt 0) {
    $filteredActions = $result.ActiveClientActions | Where-Object { 
        $_ -match 'Starting|Started' -and $_ -notmatch 'Completed|Finished|Failed'
    }
    if ($filteredActions.Count -gt 0) {
        Write-Host "`n  [ACTIVE CLIENT ACTIONS]" -ForegroundColor Magenta
        $filteredActions | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    }
}

# Only show critical errors in notes
$criticalErrors = $result.Notes | Where-Object { $_ -match 'failed|error' -and $_ -notmatch 'WinRM test failed' }
if ($criticalErrors.Count -gt 0) {
    Write-Host "`n  [ERRORS]" -ForegroundColor Red
    $criticalErrors | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
}

# Return result object only if ShowDetails is requested
if ($ShowDetails) {
    return $result
}
