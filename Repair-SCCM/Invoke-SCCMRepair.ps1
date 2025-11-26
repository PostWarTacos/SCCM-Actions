<#
.SYNOPSIS
    Automated SCCM (System Center Configuration Manager) client repair and reinstallation script.

.DESCRIPTION
    This script performs comprehensive SCCM client remediation on multiple target computers.
    It automates the complete process of:
    1. Health checking SCCM client status
    2. Removing corrupted SCCM client installations
    3. Downloading fresh installation files
    4. Rebooting target systems
    5. Reinstalling SCCM client with proper site configuration
    
    The script uses existing resource scripts via Invoke-Command -FilePath to execute
    operations remotely on target machines in non-interactive PowerShell sessions (automation). It expects numeric exit codes from child scripts (0 for success, 1 for failure, etc.) to determine remediation results. It provides detailed logging and handles
    errors gracefully, maintaining success/failure tracking for all operations.

.PARAMETER ComputerName
    Specifies the target computer(s) for SCCM remediation.
    Accepts a single computer name, an array of computer names, or pipeline input.
    If not provided, the script will prompt for a target computer list file via file dialog.
    
    Examples:
    - Single computer: -ComputerName "Computer01"
    - Multiple computers: -ComputerName @("Computer01", "Computer02", "Computer03")
    - Pipeline input: Get-Content computers.txt | .\Invoke-SCCMRepair.ps1
    
    When this parameter is not specified, the script uses interactive prompts to gather:
    - Target computer list file (selected via file dialog)
    - SCCM site code (auto-detected or manually entered)

.INPUTS
    System.String[]
        Array of computer names can be passed via the ComputerName parameter
        or through pipeline input from Get-Content or other cmdlets.
    
    System.String
        Text file containing list of target computer names (one per line)
        Selected via file dialog when ComputerName parameter is not provided.
        Located by default on the user's desktop.

.OUTPUTS
    Two result files created on the desktop:
    - success.txt: List of computers where remediation completed successfully
    - fail.txt: List of computers where remediation failed with error details

.EXAMPLE
    .\Invoke-SCCMRepair.ps1
    
    Launches the interactive script which will:
    1. Prompt for target computer list file
    2. Auto-detect or prompt for SCCM site code
    3. Process each computer in the list
    4. Generate success/failure reports on desktop

.EXAMPLE
    .\Invoke-SCCMRepair.ps1 -ComputerName "COMPUTER01"
    
    Performs SCCM remediation on a single computer named COMPUTER01.
    
.EXAMPLE
    .\Invoke-SCCMRepair.ps1 -ComputerName @("COMPUTER01", "COMPUTER02", "COMPUTER03")
    
    Performs SCCM remediation on multiple specified computers.
    
.EXAMPLE
    Get-Content "C:\computers.txt" | .\Invoke-SCCMRepair.ps1
    
    Reads computer names from a text file and pipes them to the script for processing.
    
.EXAMPLE
    Get-ADComputer -Filter "Name -like 'WS-*'" | Select-Object -ExpandProperty Name | .\Invoke-SCCMRepair.ps1
    
    Retrieves computer names from Active Directory and processes them through the remediation script.

.NOTES
    Author: Matthew Wurtz
    Date: 14-Nov-25
    Version: 1.3
    
    Prerequisites:
    - PowerShell remoting enabled on target computers
    - Administrative access to target computers
    - Network connectivity to SCCM distribution points
    - Required resource scripts in Resources subfolder:
      * Check-SCCMHealth.ps1
      * Remove-SCCM.ps1  
      * Reinstall-SCCM.ps1
    
    Supported SCCM Sites:
    - DDS: For DDS domain environments (\\scanz223\SMS_DDS\Client)
    - PCI: For PCI/DPOS domain environments (\\slrcp223\SMS_PCI\Client)
    
    Error Handling:
    - Timeout protection for user inputs (10 seconds)
    - Network connectivity validation before processing
    - Graceful failure handling with detailed error logging
    - Automatic skip of offline or inaccessible computers

.LINK
    Related Scripts:
    - Check-SCCMHealth.ps1: Validates SCCM client health status
    - Remove-SCCM.ps1: Removes existing SCCM client installation
    - Reinstall-SCCM.ps1: Installs fresh SCCM client with site configuration
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    [Alias('Computer', 'Computers', 'CN')]
    [string[]]$ComputerName
)

begin {
    # Initialize array to collect pipeline input
    $PipelineComputers = @()
}

process {
    # Collect computer names from pipeline
    if ($ComputerName) {
        $PipelineComputers += $ComputerName
    }
}

end {

#Requires -Version 5.0
#Requires -RunAsAdministrator

clear

# -------------------- FUNCTIONS -------------------- #

<#
.SYNOPSIS
    Opens a file dialog to allow user to select a target file.
    
.DESCRIPTION
    Presents a Windows Forms OpenFileDialog to the user for file selection.
    Used to select the text file containing the list of target computers.
    
.PARAMETER initialDirectory
    The directory to open the file dialog in (typically user's desktop)
    
.OUTPUTS
    String: Full path to the selected file
#>
Function Get-FileName() {
    param (
        [Parameter(Mandatory)]
        [string]$initialDirectory
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.initialDirectory = $initialDirectory
    $openFileDialog.filter = "All files (*.*)| *.*"
    $openFileDialog.ShowDialog() | Out-Null
    $openFileDialog.filename
}

<#
.SYNOPSIS
    Writes formatted log messages with timestamps and color coding.
    
.DESCRIPTION
    Provides standardized logging output with different severity levels.
    Each message includes timestamp, level indicator, and appropriate console coloring.
    
.PARAMETER Level
    Severity level: Info, Warning, Error, or Success
    
.PARAMETER Message
    The message text to display and log
#>
Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory)]
        [string]$Message,
        [Parameter(Position=1)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Default")]
        [string]$Level,
        [string]$LogFile = "$healthLogPath\HealthCheck.txt"
    )
    
    # Generate timestamp for log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes for visual identification    
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

    # Display console output with appropriate colors for each level (only when running interactively)
    switch ($Level) {
        "Default" { Write-Host $logEntry -ForegroundColor DarkGray }
        "Info"    { Write-Host $logEntry -ForegroundColor White }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Write to log file if specified
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -ErrorAction Stop
        } catch {
            # Use Write-Warning to avoid recursion when logging fails
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Prompts user for input with automatic timeout and validation.
    
.DESCRIPTION
    Displays a prompt and waits for user input with a configurable timeout.
    If no input is provided within the timeout period, the script exits.
    Optionally validates input against a list of valid values.
    
.PARAMETER Prompt
    The text prompt to display to the user
    
.PARAMETER TimeoutSeconds
    Maximum time to wait for input (default: 10 seconds)
    
.PARAMETER ValidValues
    Array of acceptable input values for validation
    
.OUTPUTS
    String: The validated user input (trimmed and uppercase)
#>
function Get-UserInputWithTimeout {
    param(
        [string]$Prompt,
        [int]$TimeoutSeconds = 10,
        [string[]]$ValidValues = @()
    )
    
    Write-LogMessage -Level Warning -Message "$Prompt"
    Write-LogMessage -Level Error -Message "Script will exit if no input provided within $TimeoutSeconds seconds"
    
    Write-Host "$Prompt" -NoNewline
    
    $userInput = ""
    $startTime = Get-Date
    $timeoutTime = $startTime.AddSeconds($TimeoutSeconds)
    
    # Clear any existing keyboard buffer
    while ([Console]::KeyAvailable) {
        [Console]::ReadKey($true) | Out-Null
    }
    
    while ((Get-Date) -lt $timeoutTime) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            
            if ($key.Key -eq 'Enter') {
                Write-Host "" # New line after Enter
                break
            }
            elseif ($key.Key -eq 'Backspace') {
                if ($userInput.Length -gt 0) {
                    $userInput = $userInput.Substring(0, $userInput.Length - 1)
                    Write-Host "`b `b" -NoNewline
                }
            }
            else {
                $userInput += $key.KeyChar
                Write-Host $key.KeyChar -NoNewline
            }
        }
        Start-Sleep -Milliseconds 50
    }
    
    # Check for timeout
    if ((Get-Date) -ge $timeoutTime) {
        Write-Host "" # New line
        Write-LogMessage -Level Error -Message "Timeout reached. No input provided. Exiting script."
        exit 1
    }
    
    # If no input provided (empty string), exit script
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        Write-LogMessage -Level Error -Message "No input provided. Exiting script."
        exit 1
    }
    
    # Validate against allowed values if provided
    $trimmedInput = $userInput.ToUpper().Trim()
    if ($ValidValues.Count -gt 0 -and $trimmedInput -notin $ValidValues) {
        Write-LogMessage -Level Error -Message "Invalid input: $userInput"
        return $null  # Invalid input - allows retry
    }
    
    return $trimmedInput
}

<#
.SYNOPSIS
    Determines the appropriate SCCM site code based on domain or user input.
    
.DESCRIPTION
    Attempts to auto-detect the SCCM site code by examining the current domain.
    If auto-detection fails or returns an unknown domain, prompts the user
    to manually enter the correct site code with validation.
    
    Supported mappings:
    - DDS domains -> DDS site code
    - PCI domains -> PCI site code  
    - DPOS domains -> PCI site code (legacy compatibility)
    
.OUTPUTS
    String: The validated SCCM site code (DDS or PCI)
#>
function Get-SiteCode{
    # Internal helper function to prompt for site code input when auto-detection fails
    function Get-SiteCodeFromUser {
        param([string]$reason)
        
        if ($reason) {
            Write-LogMessage -Level Warning -Message $reason
        }
        Write-LogMessage -Level Warning -Message "Unable to automatically determine SCCM site code."
        Write-LogMessage -Message "Known site codes:"
        Write-LogMessage -Message "  - DDS (for DDS domains)"
        Write-LogMessage -Message "  - PCI (for DPOS domains)"
        
        do {
            $code = Get-UserInputWithTimeout -Prompt "Please enter the correct site code (DDS or PCI)" -TimeoutSeconds 10 -ValidValues @("DDS", "PCI", "DPOS")
            
            if ($null -eq $code) {
                Write-LogMessage -Level Error -Message "Invalid site code. Please enter 'DDS' or 'PCI'."
                continue
            }
            
            # Convert DPOS to PCI for consistency
            if ($code -eq "DPOS") {
                $code = "PCI"
            }
            
            break
        } while ($true)
        
        Write-LogMessage -Level Success -Message "Using site code: $code"
        return $code
    }

    try {
        # Attempt to get current domain name for automatic site code detection
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        
        # Map domain names to appropriate SCCM site codes
        if ( $domain -match "DDS" ) {
            $code = "DDS"
        }
        elseif ( $domain -match "PCI" ) {
            $code = "PCI"
        }
        else {
            # Unknown domain - prompt for manual input with timeout protection
            $code = Get-SiteCodeFromUser -reason "Unknown domain detected: $domain"
        }
        return $code
    }
    catch {
        # Failed to get domain information - fallback to manual input
        Write-Error "Failed to get domain information: $_"
        $code = Get-SiteCodeFromUser -reason "Failed to get domain information"
        return $code
    }
}


# -------------------- VARIABLES -------------------- #

# Define output file paths for success/failure tracking
# These files will be created on the user's desktop for easy access
$desktop = [Environment]::GetFolderPath('Desktop')
$remediationSuccess = Join-Path $desktop "success.txt"
$remediationFail = Join-Path $desktop "fail.txt"

if (Test-Path $remediationSuccess){
    Remove-Item $remediationSuccess -Force
}
if (Test-Path $remediationFail){
    Remove-Item $remediationFail -Force
}

# Determine appropriate SCCM site code (auto-detect or prompt user)
$siteCode = Get-SiteCode
Write-LogMessage -Level Success -Message "Using SCCM site code: $siteCode"

# Build argument lists for child scripts
$HealthArgs = @()
$RemoveArgs = @($true)
$ReinstallArgs = @($siteCode, $true)

# -------------------- PREPARATION -------------------- #
# Determine target computers from parameter or file selection
if ($PipelineComputers.Count -gt 0) {
    # Use computers provided via parameter or pipeline
    $targets = $PipelineComputers
    Write-LogMessage -Level Info -Message "Using $($targets.Count) target computers provided via parameter/pipeline"
    Write-LogMessage -Level Info -Message "Target computers: $($targets -join ', ')"
} else {
    # Prompt user to select target computer list file
    # File should contain one computer name per line
    Write-LogMessage -Level Info -Message "Select target file containing list of computers..."
    $targetFile = Get-FileName -initialDirectory $desktop
    
    # Load target computer names from selected file
    $targets = Get-Content $targetFile
    Write-LogMessage -Message "Loaded $($targets.Count) target computers from: $targetFile"
}

# Build full paths to required resource scripts in Resources subfolder
# These scripts contain the actual SCCM remediation logic
$resourcesPath = Join-Path $PSScriptRoot "Resources"
$healthCheckScript = Join-Path $resourcesPath "Check-SCCMHealth.ps1"    # Validates SCCM client health
$removeScript = Join-Path $resourcesPath "Remove-SCCM.ps1"              # Removes existing SCCM client
$reinstallScript = Join-Path $resourcesPath "Reinstall-SCCM.ps1"        # Installs fresh SCCM client

# Validate that all required resource scripts exist before proceeding
$scriptPaths = @{
    'healthCheckScript' = $healthCheckScript
    'removeScript' = $removeScript
    'reinstallScript' = $reinstallScript
}

foreach ($name in $scriptPaths.Keys) {
    if (-not (Test-Path $scriptPaths[$name])) {
        Write-LogMessage -Level Error -Message "Required script file not found: $($scriptPaths[$name])"
        Write-LogMessage -Level Error -Message "Please ensure all resource scripts are present in the Resources folder"
        exit 1
    }
}

Write-LogMessage -Level Success -Message "Found all required resource scripts"
Write-LogMessage -Level Info -Message "Starting SCCM remediation process..."



# -------------------- MAIN PROCESSING LOOP -------------------- #
# This section processes each target computer through the complete remediation workflow:
# 1. Connectivity validation
# 2. Initial SCCM health check
# 3. SCCM client removal (if needed)
# 4. Installation file download
# 5. System reboot and reconnection
# 6. Fresh SCCM client installation
# 7. Result tracking and logging

foreach ( $t in $targets ){

    Write-LogMessage -message "============================================"
    Write-LogMessage -message "Starting SCCM remediation on $t"
    Write-LogMessage -message "============================================"
    
    # Validate network connectivity before attempting any remote operations
    # This prevents hanging on inaccessible machines
    Write-LogMessage -message "Testing network connection to $t"
    if ( -not ( Test-Connection $t -Count 2 -Quiet )){
        Write-LogMessage -Level Warning -Message "Unable to connect to $t. Skipping to next computer."
        "$t - Failed: Network connectivity test failed" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }
    Write-LogMessage -Level Success -Message "Network connection to $t confirmed"

    # Initialize health result variable to ensure clean state for each computer
    $healthResult = $null

    # ------------------------------------------------------------
    # STEP 1: Initial Health Check
    # ------------------------------------------------------------
    
    Write-LogMessage -Level Info -Message "--- Step 1: Initial Health Check ---"
    Write-LogMessage -message "Running SCCM health assessment on $t"
    $healthResult = $null
    try {
        # Execute health check script remotely to assess current SCCM client status
        $healthResult = Invoke-Command -ComputerName $t -FilePath $healthCheckScript -ErrorAction Stop -ErrorVariable healthError
              
        # If SCCM client is already healthy, skip the entire remediation process
        if ($healthResult -like "*Healthy*") {
            Write-LogMessage -Level Success -Message "$t SCCM client is already healthy. Skipping remediation."
            "$t - Success: Already healthy, no remediation needed" | Out-File -Append -FilePath $remediationSuccess -Encoding UTF8
            continue
        }
        else {
            Write-LogMessage -Level Error -Message "$t SCCM client is unhealthy. Proceeding with full remediation."
            Write-LogMessage -Level Warning -Message "Health check returned: '$healthResult'"
        }
    } catch {
        Write-LogMessage -Level Error -Message "Initial health check failed on $t. Error: $($_.Exception.Message)"
        Write-LogMessage -Level Error -Message "Error details: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-LogMessage -Level Error -Message "Inner exception: $($_.Exception.InnerException.Message)"
        }
        Write-LogMessage -message "Continuing with remediation despite health check failure"
    }

    # ------------------------------------------------------------
    # STEP 2: Execute Remove-SCCM Script
    # ------------------------------------------------------------

    Write-LogMessage -Level Info -Message "--- Step 2: SCCM Client Removal ---"
    Write-LogMessage -message "Removing existing SCCM client installation on $t"
    try {
        # Execute removal script to completely uninstall existing SCCM client
        # This ensures a clean slate for the subsequent reinstallation
        $removalResult = Invoke-Command -ComputerName $t -FilePath $removeScript -ArgumentList $RemoveArgs -ErrorAction Stop
        
        # Check removal results based on exit codes:
        # Accept new string return values from Remove-SCCM.ps1
        #write-host $removalResult
        Write-Host $removalResult.GetType()
        switch ($removalResult) {
            "Quick Fix Success" {
                Write-LogMessage -Level Success -Message "SCCM client quick fix successful on $t. Skipping full remediation."
                "$t - Success: Quick fix resolved SCCM issues" | Out-File -Append -FilePath $remediationSuccess -Encoding UTF8
                continue
            }
            "0" {
                Write-LogMessage -Level Success -Message "SCCM client removal completed successfully on $t"
            }
            "1" {
                Write-LogMessage -Level Error -Message "SCCM client removal failed on $t (status: '$removalResult')"
                "$t - Failed: SCCM client removal failed with errors" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
                continue
            }
        }
        
    } catch {
        Write-LogMessage -Level Error -Message "Failed to execute SCCM removal script on $t. Error: $_"
        write-host $removalResult
        "$t - Failed: SCCM client removal execution failed - $_" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 3: Download SCCM Installation Files
    # ------------------------------------------------------------

    Write-LogMessage -Level Info -Message "--- Step 3: Download SCCM Installation Files ---"
    Write-LogMessage -message "Preparing SCCM installation files for $t"
    try {
        # Determine source path based on SCCM site code
        # Each site has its own distribution point with site-specific client files
        if ( $siteCode -eq "DDS" ) {
            $cpSource = "\\scanz223\SMS_DDS\Client"     # DDS site distribution point
        }
        elseif ( $siteCode -eq "PCI" ) {
            $cpSource = "\\slrcp223\SMS_PCI\Client"     # PCI site distribution point
        }
        
        # Set standardized destination path on target computer
        # This location will be used by the reinstall script
        $cpDestination = "\\$t\c$\drivers\ccm\ccmsetup"
        $localDestPath = "C:\Drivers\ccm\ccmsetup"

        Write-LogMessage -message "Testing connection to $cpSource"
        if (Test-Path $cpSource) {
            Write-LogMessage -Level Success -Message "Path to source files validated."
        }
        else {
            throw "SCCM distribution point source not reachable: $cpSource"
        }
        
        Write-LogMessage -message "Destination: $localDestPath on $t"
        
        # Remove destination directory if it exists to delete any old install files
        if (Test-Path $cpDestination) {
            Write-LogMessage -Level Warning -Message "Removing existing destination directory on $t to delete any old CCM Setup files."
            try {
                Invoke-Command -ComputerName $t -ScriptBlock {
                    param($Path)
                    if (Test-Path $Path){
                        Remove-Item $Path -Force -Recurse -ErrorAction Stop
                    }
                } -ArgumentList $localDestPath
                if (-not (Test-Path $cpDestination)) {
                    Write-LogMessage -Level Success -Message "$localDestPath directory removed on $t."
                }
                else {
                    Write-LogMessage -Level Error -Message "Failed to remove $localDestPath directory on $t. Directory still exists after removal attempt."
                    throw "Directory removal failed"
                }
            }
            catch {
                Write-LogMessage -Level Error -Message "Error removing $localDestPath directory on $t`: $($_.Exception.Message)"
                throw $_
            }
        }
        # Create destination directory
        New-Item $cpDestination -Force -ItemType Directory | Out-Null
        
        if (Test-Path $cpDestination) {
            Write-LogMessage -Level Success -Message "Created destination directory on $t"
        }
        else {
            throw "Destination location not reachable: $cpDestination"
        }

        # Copy SCCM installation files from distribution point to target computer
        # This includes ccmsetup.exe and all required client installation files
        # Using Robocopy for improved performance and reliability with large files
        
        # OLD METHOD (commented out - had "write protected" issues):
        # Copy-Item $cpSource $cpDestination -Force -Recurse -ErrorAction Stop
        
        try {
            # Robocopy arguments for optimal performance and reliability
            # Copy directly to the original destination path structure
            $robocopyArgs = @(
                "`"$cpSource`""
                "`"$cpDestination`""
                "/E"          # Copy subdirectories including empty ones
                "/R:3"        # Retry 3 times on failed copies
                "/W:5"        # Wait 5 seconds between retries
                "/NP"         # No progress indicator (cleaner output)
                "/NFL"        # No file list (reduce log noise)
                "/NDL"        # No directory list (reduce log noise)
                "/MT:8"       # Multi-threaded copy (8 threads for performance)
            )
            
            Write-LogMessage -message "Starting Robocopy file transfer..."
            Write-LogMessage -message "Command: robocopy $($robocopyArgs -join ' ')"
            
            # Execute Robocopy
            $robocopyResult = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -Wait -PassThru -NoNewWindow
            
            # Robocopy exit codes: 0 = no files copied, 1 = files copied successfully, 2+ = errors
            if ($robocopyResult.ExitCode -le 1) {
                Write-LogMessage -Level Success -Message "SCCM installation files copied successfully to $t using Robocopy (Exit Code: $($robocopyResult.ExitCode))"
            } else {
                throw "Robocopy failed with exit code: $($robocopyResult.ExitCode)"
            }
        }
        catch {
            Write-LogMessage -Level Error -Message "Failed to copy SCCM installation files to $t. Error: $_"
            throw $_
        }

        # Verify that the main installer executable exists on target computer
        $ccmSetupPath = Join-Path $cpDestination "ccmsetup.exe"
        $verificationResult = Test-Path $ccmSetupPath
        
        if ($verificationResult) {
            Write-LogMessage -Level Success -Message "Verified ccmsetup.exe exists on $t"
        }
        else {
            throw "ccmsetup.exe not found on $t after file copy operation"
        }

        Write-LogMessage -Level Success -Message "SCCM installation files prepared successfully on $t"
    } catch {
        Write-LogMessage -Level Error -Message "Failed to download SCCM installation files on $t. Error: $_"
        "$t - Failed: File download error - $_" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }
    
    # ------------------------------------------------------------
    # STEP 4: Reboot and Wait for Connection
    # ------------------------------------------------------------

    Write-LogMessage -Level Info -Message "--- Step 4: System Reboot and Reconnection ---"
    Write-LogMessage -Message "Initiating system reboot on $t"
    try {
        # Initiate immediate reboot on target computer
        # Reboot is necessary to clear any locked SCCM processes and ensure clean installation
        Invoke-Command -ComputerName $t -ScriptBlock { shutdown /r /t 0 /f } -ErrorAction Stop
        Write-LogMessage -Level Success -Message "Reboot command sent to $t"
        
        # Monitor system until it goes offline (indicates reboot has started)
        Write-LogMessage -message "Waiting for $t to go offline (reboot initiation)..."
        do {
            Start-Sleep -Seconds 5
            $offline = -not (Test-Connection $t -Count 1 -Quiet)
        } while (-not $offline)
        
        Write-LogMessage -Level Success -Message "$t has gone offline - reboot initiated successfully"
        
        # Monitor system until it comes back online (indicates boot completion)
        Write-LogMessage -message "Waiting for $t to come back online after reboot..."
        $maxWaitTime = 600  # 10 minutes maximum wait time (configurable)
        $waitTime = 0
        $online = $false
        
        do {
            Start-Sleep -Seconds 10
            $waitTime += 10
            $online = Test-Connection $t -Count 2 -Quiet
            
            # Provide periodic status updates to user (every 60 seconds)
            if ($waitTime % 60 -eq 0) {
                Write-LogMessage -message "Still waiting for $t to come online... ($waitTime seconds elapsed)"
            }
            
        } while (-not $online -and $waitTime -lt $maxWaitTime)
        
        if ($online) {
            Write-LogMessage -Level Success -Message "$t is back online after reboot"
            
            # Allow additional time for Windows services and processes to fully initialize
            # This prevents issues with PowerShell remoting and SCCM installation
            Write-LogMessage -message "Waiting for system stabilization (60 seconds)..."
            Start-Sleep -Seconds 60
            Write-LogMessage -Level Success -Message "System stabilization wait completed for $t"
        } else {
            Write-LogMessage -Level Error -Message "$t failed to come back online within $maxWaitTime seconds"
            "$t - Failed: System did not come back online after reboot (timeout: $maxWaitTime seconds)" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
            continue
        }
        
    } catch {
        Write-LogMessage -Level Error -Message "Failed to reboot $t. Error: $_"
        "$t - Failed: Reboot process error - $_" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 5: Execute Reinstall-SCCM Script  
    # ------------------------------------------------------------

    Write-LogMessage -Level Info -Message "--- Step 5: SCCM Client Reinstallation ---"
    Write-LogMessage -message "Installing fresh SCCM client on $t with site code: $siteCode"
    try {
        # Execute reinstallation script with appropriate site code parameter
        # This script will use the previously downloaded installation files
        Invoke-Command -ComputerName $t -FilePath $reinstallScript -ArgumentList $ReinstallArgs -ErrorAction Stop
        Write-LogMessage -Level Success -Message "SCCM client reinstallation completed successfully on $t (Site: $siteCode)"
    } catch {
        Write-LogMessage -Level Error -Message "Failed to execute SCCM reinstall script on $t. Error: $_"
        "$t - Failed: SCCM client installation failed - $_" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        continue
    }

    # ------------------------------------------------------------
    # STEP 6: Record Results
    # ------------------------------------------------------------

    Write-LogMessage -message "--- Step 6: Results Recording ---"

    # Record successful completion of all remediation steps
    # Note: Individual resource scripts handle their own success/failure validation
    # This indicates that all remediation steps were executed without errors
    "$t - Success: All remediation steps completed" | Out-File -Append -FilePath $remediationSuccess -Encoding UTF8
    Write-LogMessage -Level Success -Message "$t - All remediation steps completed successfully"
}

# -------------------- END OF MAIN PROCESSING LOOP -------------------- #

# -------------------- COMPLETION AND RESULTS SUMMARY -------------------- #
# Processing of all target computers has completed
# Results have been written to desktop files for review

Write-LogMessage -message "============================================"
Write-LogMessage -message "SCCM Remediation Process Completed"
Write-LogMessage -message "============================================"

# Display final results summary with file locations
Write-LogMessage -message "Remediation Results Summary:"
Write-LogMessage -message "  Successful computers logged to: $remediationSuccess"
Write-LogMessage -message "  Failed computers logged to: $remediationFail"

# Count results for final statistics
$successCount = 0
$failCount = 0

if (Test-Path $remediationSuccess) {
    $successCount = (Get-Content $remediationSuccess).Count
}

if (Test-Path $remediationFail) {
    $failCount = (Get-Content $remediationFail).Count
}

Write-LogMessage -message "Final Statistics:"
Write-LogMessage -message "  Successful: $successCount computers"
Write-LogMessage -message "  Failed: $failCount computers"
Write-LogMessage -message "  Total Processed: $($successCount + $failCount) computers"

Write-LogMessage -message "Review the result files on your desktop for detailed information."
Write-LogMessage -message "SCCM remediation script execution complete."

} # End of 'end' block