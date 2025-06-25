<#
.SYNOPSIS
    Detects unused SCCM objects: Applications, Collections, Deployments, Task Sequences,
    Configuration Items, and Baselines. Generates a separate CSV file for each unused type.

.NOTES
    Run from an SCCM PowerShell environment with site drive loaded (e.g., XYZ:).
#>

clear-host

Import-Module ( $ENV:SMS_ADMIN_UI_PATH.Substring( 0, $ENV:SMS_ADMIN_UI_PATH.Length - 5 ) + '\ConfigurationManager.psd1')
$siteCode = Get-PSDrive -PSProvider CMSite | Select-Object -First 1 -ExpandProperty Name
Set-Location "$siteCode`:"
if ( $siteCode -eq "DDS" ){
    [string]$siteServer = "SCANZ223"
}
elseif( $siteCode -eq "PCI" ){
    [string]$siteServer = "SLRCP223"
}

$date = Get-Date
$fileDate = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportPath = "C:\SCCM_Cleanup_$fileDate"
New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
Write-Host "[$($date.ToString('MM/dd/yyyy HH:mm'))] Script started"
Write-Host "Set drive location to $siteCode`:"
Write-Host "Directory created at $exportPath"

function Export-Unused {
    param( $Objects, $TypeName )
    $file = Join-Path $exportPath "$TypeName.csv"
    $Objects | Export-Csv -NoTypeInformation -Path $file
    Write-Host "$TypeName exported to $file"
}

# -------------------- Variables -------------------- #

# List of ALL items
$appList = Get-CMApplication -WarningAction SilentlyContinue
$tsList = Get-CMTaskSequence -WarningAction SilentlyContinue
$baselineList = Get-CMBaseline -WarningAction SilentlyContinue
$ciList = Get-CMConfigurationItem -WarningAction SilentlyContinue
$devCollList = Get-CMDeviceCollection -WarningAction SilentlyContinue
$ciList = Get-CMConfigurationItem -WarningAction SilentlyContinue

# Deployed lists
$deployedApps = Get-CMApplicationDeployment -WarningAction SilentlyContinue
$deploymentColls = Get-CMDeployment | select -ExpandProperty CollectionName
$deployedPackageIDs = Get-CMTaskSequenceDeployment -WarningAction SilentlyContinue |
    Group-Object packageid | Select-Object -ExpandProperty name
$deployedBaselinesID = Get-CMBaselineDeployment -WarningAction SilentlyContinue |
    Select-Object -ExpandProperty AssignedCI_UniqueID
$deviceLimitingIDs = $devCollList | Select-Object -ExpandProperty LimitToCollectionID

# CIM commands
$cimApps = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ApplicationLatest
$ciLinks = Get-CimInstance -computername $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_CIRelation |
    Where-Object { $_.RelationType -eq 1 -and $baselineIDs -contains $_.FromCIID } |
    Select-Object -ExpandProperty ToCIID -Unique
$appCIs = Get-CimInstance -computername $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ConfigurationItem |
    Where-Object { $_.CIType_Id -eq 2 }
$cimDevCollections = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_Collection
$scheduleDeployments = Get-CimInstance -computername $siteServer -Namespace "root/SMS/site_$siteCode" -ClassName SMS_AdvertisementInfo
$legacyPackages = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$siteCode" -ClassName SMS_Package
$cimBaseline = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ConfigurationBaselineInfo
$cimTS = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_TaskSequencePackage
$cimCI = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ConfigurationItemLatest


# -------------------- Arrays -------------------- #

$unusedDevColl = @()
$unusedApps = @()
$expiredDeployments = @()
$unusedTS = @()
$unusedCIs = @()
$unusedBaselines = @()

$date = get-date
Write-Host "[$($date.ToString('MM/dd/yyyy HH:mm'))] All variables created"

# -------------------- Unused Device Collections (no members + no deployments) -------------------- #

foreach ($col in $devCollList) {
    if (
        ( $col.MemberCount -eq 0 ) -and
        ( $col.name -notin $deploymentColls ) -and
        ( -not $col.IsBuiltIn ) -and
        ( $deviceLimitingIDs -notcontains $col.CollectionID )
    ) {
        $cim = $cimDevCollections | Where-Object { $_.CollectionID -eq $col.CollectionID }
        $unusedDevColl += [PSCustomObject]@{
            Name                 = $col.Name
            CollectionID         = $col.CollectionID
            LimitingCollection   = $col.LimitToCollectionName
            FolderPath           = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedDevColl -TypeName "Unused_Device_Collections"


# -------------------- Unused Applications (checking TS, deployed, baseline, and CI) -------------------- #

foreach ( $a in $appList ) {
    $escapedModelName = [WildcardPattern]::Escape($a.ModelName)
    $escapedPackageID = [WildcardPattern]::Escape($a.PackageID)
    
    $inTS = $tsList | Where-Object {
        $_.Sequence -like "*$escapedModelName*"
    }
    
    $inCI = $ciList | Where-Object {
        $_.Sequence -like "*$escapedPackageID*"
    }

    $isDeployed = $deployedApps | Where-Object {
        $_.applicationname -contains $a.LocalizedDisplayName -and
        $_.AssignedCI_UniqueID -contains $a.CI_UniqueID
    }

    $inBaseline = $appCIs | Where-Object { $ciLinks -contains $_.CI_ID } 

    if  ( 
        -not $isDeployed -and
        -not $inTS -and
        -not $inBaseline -and
        -not $inCI
    ) {
        $folderPath = ($devFolders | Where-Object { $_.ID -eq $a.ContainerNodeNodeID }).Path
        $cim = $cimApps | Where-Object { $_.CI_UniqueID -eq $a.CI_UniqueID }
        $unusedApps += [PSCustomObject]@{
            ApplicationName = $a.LocalizedDisplayName
            CI_UniqueID     = $a.CI_UniqueID
            FolderPath      = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedApps -TypeName "Unused_Applications"


# -------------------- Unused Configuration Items (no deployment, not in baseline) -------------------- #

foreach ( $ci in $ciList ) {
    if ( -not $ci.InUse -and -not $ci.IsAssigned ) {
        $cim = $cimCI | Where-Object { $_.CI_UniqueID -eq $ci.CI_UniqueID }
        $unusedCIs += [PSCustomObject]@{
            Name        = $ci.LocalizedDisplayName
            CI_UniqueID = $ci.CI_UniqueID
            FolderPath  = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedCIs -TypeName "Unused_ConfigurationItems"


# -------------------- Expired Deployments -------------------- #

# Build a dictionary: PackageID > ObjectPath
$pkgToPath = @{}
foreach ( $pkg in $legacyPackages + $cimTS ) {
    if ( $pkg.PackageID -and $pkg.ObjectPath ) {
        $pkgToPath[$pkg.PackageID] = $pkg.ObjectPath
    }
}

foreach ($dep in $scheduleDeployments) {
    if ( $dep.ExpirationTime -and $dep.ExpirationTime -lt ( Get-Date )) {
        $objectPath = $pkgToPath[$dep.PackageID]

        $expiredDeployments += [PSCustomObject]@{
            AdvertisementName = $dep.AdvertisementName
            PackageID         = $dep.PackageID
            ObjectPath        = $objectPath
            EndTime           = $dep.ExpirationTime.ToString("MM/dd/yyyy HH:mm")
        }
    }
}
Export-Unused -Objects $expiredDeployments -TypeName "Expired_Deployments"


# -------------------- Unused Task Sequences (not deployed) -------------------- #
<#
foreach ( $ts in $tsList ) {
    if (
        $ts.PackageID -notin $deployedPackageIDs
    ){
        $cim = $cimTS | Where-Object { $_.PackageID -eq $ts.PackageID }
        $unusedTS += [PSCustomObject]@{
            Name             = $ts.Name
            PackageID        = $ts.PackageID
            FolderPath       = $cim.ObjectPath
        }
    }
    foreach ( $c in $unusedDevColl ){
        $escapedColl = [WildcardPattern]::Escape($col.collectionID)
        if (
            $ts.Sequence -like "*$escapedColl*"
        ){
            $cim = $cimTS | Where-Object { $_.PackageID -eq $ts.PackageID }
            $unusedTS += [PSCustomObject]@{
                Name             = $ts.Name
                PackageID        = $ts.PackageID
                FolderPath       = $cim.ObjectPath
            }
        }
    }
        foreach ( $a in $unusedApps ){
        $escapedAppName = [WildcardPattern]::Escape($a.LocalizedDisplayName)
        $escapedAppCi = [WildcardPattern]::Escape($a.CI_UniqueID)
        if (
            $ts.Sequence -like "*$escapedAppName*" -or
            $ts.Sequence -like "*$escapedAppCi*"
        ){
            $cim = $cimTS | Where-Object { $_.PackageID -eq $ts.PackageID }
            $unusedTS += [PSCustomObject]@{
                Name             = $ts.Name
                PackageID        = $ts.PackageID
                FolderPath       = $cim.ObjectPath
            }
        }
    }
}
#>

#version 2
foreach ( $ts in $tsList ) {
    
    if ( [string]$ts.PackageID -notin $deployedPackageIDs ){
        $cim = $cimTS | Where-Object { $_.PackageID -eq $ts.PackageID }
        $unusedTS += [PSCustomObject]@{
            Name       = $ts.Name
            PackageID  = $ts.PackageID
            FolderPath = $cim.ObjectPath
        }
        $directCount++
        continue
    }
    
    $isUsedByUnusedColl = $false
    foreach ( $c in $unusedDevColl ){
        $escapedColl = [WildcardPattern]::Escape($c.CollectionID)
        if ( $ts.Sequence -like "*$escapedColl*" ){
            $isUsedByUnusedColl = $true
            $collCount++
            break
        }
    } 

    $isUsedByUnusedApp = $false
    foreach ( $a in $unusedApps ){
        $escapedAppName = [WildcardPattern]::Escape($a.LocalizedDisplayName)
        $escapedAppCi = [WildcardPattern]::Escape($a.CI_UniqueID)
        if (
            $ts.Sequence -like "*$escapedAppName*" -and
            $ts.Sequence -like "*$escapedAppCi*"
         ){
            $isUsedByUnusedApp = $true
            $appCount++
            break
        }
    }

    if (
        $isUnusedDirectly -or
        $isUsedByUnusedColl -or
        $isUsedByUnusedApp
    ){
        $cim = $cimTS | Where-Object { $_.PackageID -eq $ts.PackageID }
        $unusedTS += [PSCustomObject]@{
            Name       = $ts.Name
            PackageID  = $ts.PackageID
            FolderPath = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedTS -TypeName "Unused_TaskSequences"


# -------------------- Unused Configuration Baselines (not deployed) -------------------- #

ForEach ( $b in $baselineList ) {
    if ( $b.CI_UniqueID -notin $deployedBaselinesID ){
        $cim = $cimBaseline | Where-Object { $_.CI_UniqueID -eq $b.CI_UniqueID }
        
        $unusedBaselines += [PSCustomObject]@{
            Name                 = $b.LocalizedDisplayName
            CI_UniqueID          = $b.CI_UniqueID
            FolderPath           = $cim.ObjectPath
        }        
    }
}
Export-Unused -Objects $unusedBaselines -TypeName "Unused_ConfigurationBaselines"

$date = get-date
Write-Host "[$($date.ToString('MM/dd/yyyy HH:mm'))] All exports complete. Files saved to: $exportPath"