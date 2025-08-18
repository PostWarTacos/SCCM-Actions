<#
.SYNOPSIS
    Retrieves SCCM deployment information for deployments created or modified within the last X hours.

.DESCRIPTION
    This script retrieves comprehensive deployment information from SCCM including:
    - Deployment name
    - Scheduled time
    - Available time
    - Person that created it
    - Person that last modified it
    
    Filters deployments based on creation or modification time within the specified hours.

.PARAMETER Hours
    Number of hours to look back for deployments. Default is 24 hours.

.PARAMETER ExportPath
    Path to export the results. If not specified, results will be displayed in the console.

.EXAMPLE
    .\Get-SCCMScheduled -Hours 48
    Gets all deployments created or modified in the last 48 hours.

.EXAMPLE
    .\Get-SCCMScheduled -Hours 12 -ExportPath "C:\Reports\SCCM_Deployments.csv"
    Gets deployments from last 12 hours and exports to CSV.

.NOTES
    Run from an SCCM PowerShell environment with site drive loaded.
    Author: Matthew Wurtz
    Date: August 11, 2025
#>

param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 500,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath
)

Clear-Host

# Import SCCM PowerShell module
try {
    Import-Module ($ENV:SMS_ADMIN_UI_PATH.Substring(0, $ENV:SMS_ADMIN_UI_PATH.Length - 5) + '\ConfigurationManager.psd1') -ErrorAction Stop
    Write-Host "SCCM PowerShell module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import SCCM PowerShell module. Ensure you're running from an SCCM console environment."
    exit 1
}

# Get site code and server
$siteCode = Get-PSDrive -PSProvider CMSite | Select-Object -First 1 -ExpandProperty Name
if (-not $siteCode) {
    Write-Error "No SCCM site drive found. Ensure SCCM PowerShell environment is properly configured."
    exit 1
}

Set-Location "$siteCode`:"

# Determine site server based on site code (adjust as needed for your environment)
if ($siteCode -eq "DDS") {
    [string]$siteServer = "SCANZ223"
} elseif ($siteCode -eq "PCI") {
    [string]$siteServer = "SLRCP223"
} else {
    Write-Warning "Could not determine site server automatically. Please modify the script to include your site server."
    pause
    exit
}

# Example: Multicolored output in PowerShell
Write-Host "Connected to site: " -NoNewline
Write-Host $siteCode -ForegroundColor Green -NoNewline
Write-Host " on server: " -NoNewline
Write-Host $siteServer -ForegroundColor Green

# Calculate cutoff time
$cutoffTime = (Get-Date).AddHours(-$Hours)
Write-Host "Looking for deployments created or modified since: $($cutoffTime.ToString('MM/dd/yyyy HH:mm:ss'))" -ForegroundColor Yellow

# Initialize results array
$deploymentResults = @()

Write-Host "Retrieving deployment information..." -ForegroundColor Cyan

try {
    # Get Application Deployments
    Write-Host "  - Processing Application Deployments..." -ForegroundColor Gray
    $appDeployments = Get-CMApplicationDeployment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    foreach ($deployment in $appDeployments) {
        # Get additional deployment details from WMI
        try {
            $wmiDeployment = Get-WmiObject -Class SMS_ApplicationAssignment -Namespace "root\SMS\site_$siteCode" -ComputerName $siteServer -Filter "AssignmentID = '$($deployment.AssignmentID)'" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($wmiDeployment) {
                $createdDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.CreationTime)
                $modifiedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.LastModificationTime)
                
                # Check if deployment was created or modified within the specified timeframe
                if ($createdDate -ge $cutoffTime -or $modifiedDate -ge $cutoffTime) {
                    $deploymentResults += [PSCustomObject]@{
                        DeploymentType = "Application"
                        DeploymentName = $deployment.ApplicationName
                        CollectionName = $deployment.CollectionName
                        ScheduledTime = if ($deployment.StartTime) { $deployment.StartTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Not Scheduled" }
                        AvailableTime = if ($deployment.StartTime) { $deployment.StartTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Immediately" }
                        DeadlineTime = if ($deployment.DeadlineTime) { $deployment.DeadlineTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "No Deadline" }
                        CreatedBy = $wmiDeployment.CreatedBy
                        CreatedDate = $createdDate.ToString('MM/dd/yyyy HH:mm:ss')
                        LastModifiedBy = $wmiDeployment.LastModifiedBy
                        LastModifiedDate = $modifiedDate.ToString('MM/dd/yyyy HH:mm:ss')
                        Purpose = $deployment.Purpose
                        AssignmentID = $deployment.AssignmentID
                    }
                }
            }
        } catch {
            Write-Warning "Could not retrieve WMI data for application deployment: $($deployment.ApplicationName)"
        }
    }
    
    # Get Package/Program Deployments
    Write-Host "  - Processing Package Deployments..." -ForegroundColor Gray
    $packageDeployments = Get-CMPackageDeployment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    foreach ($deployment in $packageDeployments) {
        try {
            $wmiDeployment = Get-WmiObject -Class SMS_Advertisement -Namespace "root\SMS\site_$siteCode" -ComputerName $siteServer -Filter "AdvertisementID = '$($deployment.AdvertisementID)'" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($wmiDeployment) {
                $createdDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.SourceDate)
                $modifiedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.TimeLastModified)
                
                if ($createdDate -ge $cutoffTime -or $modifiedDate -ge $cutoffTime) {
                    $deploymentResults += [PSCustomObject]@{
                        DeploymentType = "Package"
                        DeploymentName = "$($deployment.AdvertisementName) - $($deployment.ProgramName)"
                        CollectionName = $deployment.CollectionName
                        ScheduledTime = if ($deployment.PresentTime) { $deployment.PresentTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Not Scheduled" }
                        AvailableTime = if ($deployment.PresentTime) { $deployment.PresentTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Immediately" }
                        DeadlineTime = if ($deployment.ExpirationTime) { $deployment.ExpirationTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "No Deadline" }
                        CreatedBy = $wmiDeployment.SourceSite
                        CreatedDate = $createdDate.ToString('MM/dd/yyyy HH:mm:ss')
                        LastModifiedBy = $wmiDeployment.SourceSite
                        LastModifiedDate = $modifiedDate.ToString('MM/dd/yyyy HH:mm:ss')
                        Purpose = "N/A"
                        AssignmentID = $deployment.AdvertisementID
                    }
                }
            }
        } catch {
            Write-Warning "Could not retrieve WMI data for package deployment: $($deployment.AdvertisementName)"
        }
    }
    
    # Get Task Sequence Deployments
    Write-Host "  - Processing Task Sequence Deployments..." -ForegroundColor Gray
    $tsDeployments = Get-CMTaskSequenceDeployment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    foreach ($deployment in $tsDeployments) {
        try {
            $wmiDeployment = Get-WmiObject -Class SMS_Advertisement -Namespace "root\SMS\site_$siteCode" -ComputerName $siteServer -Filter "AdvertisementID = '$($deployment.AdvertisementID)'" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($wmiDeployment) {
                $createdDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.SourceDate)
                $modifiedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.TimeLastModified)
                
                if ($createdDate -ge $cutoffTime -or $modifiedDate -ge $cutoffTime) {
                    $deploymentResults += [PSCustomObject]@{
                        DeploymentType = "Task Sequence"
                        DeploymentName = $deployment.AdvertisementName
                        CollectionName = $deployment.CollectionName
                        ScheduledTime = if ($deployment.PresentTime) { $deployment.PresentTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Not Scheduled" }
                        AvailableTime = if ($deployment.PresentTime) { $deployment.PresentTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Immediately" }
                        DeadlineTime = if ($deployment.ExpirationTime) { $deployment.ExpirationTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "No Deadline" }
                        CreatedBy = $wmiDeployment.SourceSite
                        CreatedDate = $createdDate.ToString('MM/dd/yyyy HH:mm:ss')
                        LastModifiedBy = $wmiDeployment.SourceSite
                        LastModifiedDate = $modifiedDate.ToString('MM/dd/yyyy HH:mm:ss')
                        Purpose = "N/A"
                        AssignmentID = $deployment.AdvertisementID
                    }
                }
            }
        } catch {
            Write-Warning "Could not retrieve WMI data for task sequence deployment: $($deployment.AdvertisementName)"
        }
    }
    
    # Get Configuration Baseline Deployments
    Write-Host "  - Processing Configuration Baseline Deployments..." -ForegroundColor Gray
    $baselineDeployments = Get-CMBaselineDeployment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    foreach ($deployment in $baselineDeployments) {
        try {
            $wmiDeployment = Get-WmiObject -Class SMS_BaselineAssignment -Namespace "root\SMS\site_$siteCode" -ComputerName $siteServer -Filter "AssignmentID = '$($deployment.AssignmentID)'" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($wmiDeployment) {
                $createdDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.CreationTime)
                $modifiedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDeployment.LastModificationTime)
                
                if ($createdDate -ge $cutoffTime -or $modifiedDate -ge $cutoffTime) {
                    $deploymentResults += [PSCustomObject]@{
                        DeploymentType = "Configuration Baseline"
                        DeploymentName = $deployment.Assignementname
                        CollectionName = $deployment.CollectionName
                        ScheduledTime = if ($deployment.StartTime) { $deployment.StartTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Not Scheduled" }
                        AvailableTime = if ($deployment.StartTime) { $deployment.StartTime.ToString('MM/dd/yyyy HH:mm:ss') } else { "Immediately" }
                        DeadlineTime = "N/A"
                        CreatedBy = $wmiDeployment.CreatedBy
                        CreatedDate = $createdDate.ToString('MM/dd/yyyy HH:mm:ss')
                        LastModifiedBy = $wmiDeployment.LastModifiedBy
                        LastModifiedDate = $modifiedDate.ToString('MM/dd/yyyy HH:mm:ss')
                        Purpose = "N/A"
                        AssignmentID = $deployment.AssignmentID
                    }
                }
            }
        } catch {
            Write-Warning "Could not retrieve WMI data for baseline deployment: $($deployment.Assignementname)"
        }
    }
    
} catch {
    Write-Error "An error occurred while retrieving deployment information: $($_.Exception.Message)"
    exit 1
}

# Sort results by creation date (newest first)
$deploymentResults = $deploymentResults | Sort-Object { [DateTime]$_.CreatedDate } -Descending

# Display results
Write-Host "`nFound $($deploymentResults.Count) deployment(s) created or modified in the last $Hours hours, since $($cutoffTime.ToString('MM/dd/yyyy HH:mm:ss')):" -ForegroundColor Green

if ($deploymentResults.Count -gt 0) {
    if ($ExportPath) {
        # Export to CSV
        try {
            $deploymentResults | Export-Csv -NoTypeInformation -Path $ExportPath
            Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export results to $ExportPath : $($_.Exception.Message)"
        }
    } else {
        # Display in console
        $deploymentResults | Format-Table -AutoSize -Wrap
    }
    
    # Summary by deployment type
    Write-Host "`nSummary by Deployment Type:" -ForegroundColor Yellow
    $deploymentResults | Group-Object DeploymentType | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Cyan
    }
} else {
    Write-Host "No deployments found matching the criteria." -ForegroundColor Yellow
}

Write-Host "`nScript completed successfully." -ForegroundColor Green