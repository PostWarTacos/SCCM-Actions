
<#
.SYNOPSIS
    Detects unused SCCM objects: Applications, Collections, Deployments, Task Sequences,
    Configuration Items, and Baselines. Generates a separate CSV file for each unused type.

.NOTES
    Run from an SCCM PowerShell environment with site drive loaded (e.g., XYZ:).
#>

Import-Module ( $ENV:SMS_ADMIN_UI_PATH.Substring( 0, $ENV:SMS_ADMIN_UI_PATH.Length - 5 ) + '\ConfigurationManager.psd1')
$siteCode = Get-PSDrive -PSProvider CMSite | Select-Object -First 1 -ExpandProperty Name
Set-Location "$siteCode`:"
if ( $siteCode -eq "DDS" ){
    [string]$siteServer = "SCANZ223"
}
elseif( $siteCode -eq "PCI" ){
    [string]$siteServer = "SLRCP223"
}

$now = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportPath = "C:\SCCM_Cleanup_$now"
New-Item -ItemType Directory -Path $exportPath -Force | Out-Null

function Export-Unused {
    param( $Objects, $TypeName )
    $file = Join-Path $exportPath "$TypeName.csv"
    $Objects | Export-Csv -NoTypeInformation -Path $file
    Write-Host "$TypeName exported to $file"
}

# 1. Unused Applications (checking TS, deployed, baseline, and CI)
$apps = Get-CMApplication -WarningAction SilentlyContinue
$deployedApps = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "Application" } |
    Select-Object -ExpandProperty SoftwareName
$tsList = Get-CMTaskSequence -WarningAction SilentlyContinue
$baselines = Get-CMBaseline -WarningAction SilentlyContinue
$usedCI_IDs = $baselines.CIRelation | ForEach-Object { $_.CI_ID } | Select-Object -Unique
$cimApps = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ApplicationLatest
$unusedApps = @()

foreach ( $a in $apps ) {
    $name = $a.LocalizedDisplayName
    $ci = $a.CI_UniqueID
    $id = $a.CI_ID

    $isDeployed = $deployedApps -contains $name
    $inTS = $tsList | Where-Object { ( [xml]$_.Sequence ).InnerXml -match $ci }
    $inBaseline = $usedCI_IDs -contains $app.CI_ID
    $inCI = (Get-CMConfigurationItem -WarningAction SilentlyContinue | Where-Object { $_.References -contains $id }).Count -gt 0

    if  ( 
        -not $isDeployed -and
        -not $inTS -and
        -not $inBaseline -and
        -not $inCI
    ) {
        $folderPath = ($devFolders | Where-Object { $_.ID -eq $a.ContainerNodeNodeID }).Path
        $cim = $cimApps | Where-Object { $_.CI_ID -eq $a.CI_ID }
        $unusedApps += [PSCustomObject]@{
            ApplicationName = $name
            CI_ID           = $id
            FolderPath      = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedApps -TypeName "Unused_Applications"

# 2. Unused Device Collections (no members + no deployments)
$deviceCollections = Get-CMDeviceCollection
$deviceLimitingIDs = $deviceCollections | Select-Object -ExpandProperty LimitToCollectionID
$cimDevCollections = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_Collection
$unusedDeviceCollections = @()

foreach ($col in $deviceCollections) {
    if (
        ( $col.MemberCount -eq 0 ) -and
        ( -not (Get-CMDeployment -CollectionName $col.Name )) -and
        ( -not $col.IsBuiltIn ) -and
        ( $deviceLimitingIDs -notcontains $col.CollectionID )
    ) {
        $cim = $cimDevCollections | Where-Object { $_.CollectionID -eq $col.CollectionID }
        $unusedDeviceCollections += [PSCustomObject]@{
            Name                 = $col.Name
            CollectionID         = $col.CollectionID
            MemberCount          = $col.MemberCount
            LimitingCollection   = $col.LimitToCollectionName
            FolderPath           = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedDeviceCollections -TypeName "Unused_Device_Collections"

# 3. Expired Deployments
$scheduleDeployments = Get-CimInstance -computername $siteServer -Namespace "root/SMS/site_$siteCode" -ClassName SMS_AdvertisementInfo
$legacyPackages = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$siteCode" -ClassName SMS_Package
$tsPackages     = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$siteCode" -ClassName SMS_TaskSequencePackage

# Build a dictionary: PackageID > ObjectPath
$pkgToPath = @{}
foreach ( $pkg in $legacyPackages + $tsPackages ) {
    if ( $pkg.PackageID -and $pkg.ObjectPath ) {
        $pkgToPath[$pkg.PackageID] = $pkg.ObjectPath
    }
}

$expiredDeployments = foreach ($dep in $scheduleDeployments) {
    if ( $dep.ExpirationTime -and $dep.ExpirationTime -lt ( Get-Date )) {
        $objectPath = $pkgToPath[$dep.PackageID]

        [PSCustomObject]@{
            AdvertisementName = $dep.AdvertisementName
            PackageID         = $dep.PackageID
            ObjectPath        = $objectPath
            EndTime           = $dep.ExpirationTime.ToString("MM/dd/yyyy HH:mm")
        }
    }
}
Export-Unused -Objects $unusedDeployments -TypeName "Expired_Deployments"

# 4. Unused Task Sequences (not deployed)
$deployedTS = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "TaskSequence" } |
    Select-Object PackageName
$cimTS = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_TaskSequencePackage
$taskSeqs = Get-CMTaskSequence -WarningAction SilentlyContinue
$unusedTS = @()

foreach ( $ts in $taskSeqs ) {
    if (
        $ts.Name -notin $deployedTS
    ){
        $cim = $cimTS | Where-Object { $_.PackageID -eq $ts.PackageID }
        $unusedTS += [PSCustomObject]@{
            Name                 = $ts.Name
            CollectionID         = $ts.PackageID
            FolderPath           = $cim.ObjectPath
        }
    }
}
Export-Unused -Objects $unusedTS -TypeName "Unused_TaskSequences"

# 5. Unused Configuration Items (no deployment, not in baseline)
$allCI = Get-CMConfigurationItem -WarningAction SilentlyContinue
$cimCI = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ConfigurationItem
$usedCIs = @()
$unusedCIs = @()

foreach ( $baseline in $baselines ) { $usedCIs += $baseline.CIRelation }
$usedCIIDs = $usedCIs | Select-Object -ExpandProperty CI_ID -Unique
$unusedCIs = $allCI | Where-Object { $_.CI_ID -notin $usedCIIDs }

ForEach ( $ci in $unusedCIs ) {
    $cim = $cimCI | Where-Object { $_.CI_ID -eq $ci.CI_ID }
    $unusedCIs += [PSCustomObject]@{
        Name                 = $cim.LocalizedDisplayName
        CollectionID         = $ci.CI_ID
        FolderPath           = $cim.ObjectPath
    }
}
Export-Unused -Objects $unusedCIs -TypeName "Unused_ConfigurationItems"

# 6. Unused Configuration Baselines (not deployed)
# $baselines is set earlier
$deployedBaselines = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "ConfigurationBaseline" } |
    Select-Object -ExpandProperty SoftwareName
$cimBaseline = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ConfigurationBaselineInfo
$unusedBaselines = @()

ForEach ( $b in $baselines ) {
    if (
        $_.LocalizedDisplayName -notin $deployedBaselines
    ){
        $cim = $cimBaseline | Where-Object { $_.CI_ID -eq $b.CI_ID }
        $unusedBaselines += [PSCustomObject]@{
            Name                 = $b.LocalizedDisplayName
            CollectionID         = $ci.CI_ID
            FolderPath           = $cim.ObjectPath
        }        
    }
}
Export-Unused -Objects $unusedBaselines -TypeName "Unused_ConfigurationBaselines"

Write-Host "All exports complete. Files saved to: $exportPath"