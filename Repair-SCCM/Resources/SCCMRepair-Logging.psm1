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
    $prefix = switch ($Level) {
        "Info"    { "[*]" }
        "Warning" { "[!]" }
        "Error"   { "[!!!]" }
        "Success" { "[+]" }
        default    { "[*]" }
    }
    $logEntry = "[$timestamp] $prefix $Message"
    if ($PSBoundParameters.ContainsKey('Level')) {
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
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
    if (-not $global:healthLog) {
        $global:healthLog = [System.Collections.ArrayList]@()
    }
    $global:healthLog.Add($logEntry) | Out-Null
}

Export-ModuleMember -Function Write-LogMessage
