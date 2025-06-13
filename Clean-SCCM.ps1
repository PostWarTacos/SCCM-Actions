
<#
.SYNOPSIS
    Detects unused SCCM objects: Applications, Collections, Deployments, Task Sequences,
    Configuration Items, and Baselines. Generates a separate CSV file for each unused type.

.NOTES
    Run from an SCCM PowerShell environment with site drive loaded (e.g., XYZ:).
#>

Import-Module ($ENV:SMS_ADMIN_UI_PATH.Substring(0,$ENV:SMS_ADMIN_UI_PATH.Length-5) + '\ConfigurationManager.psd1')
$siteCode = Get-PSDrive -PSProvider CMSite | Select-Object -First 1 -ExpandProperty Name
Set-Location "$siteCode`:"

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
$deployedApps = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "Application" } | Select-Object -ExpandProperty SoftwareName
$tsList = Get-CMTaskSequence -WarningAction SilentlyContinue
$baselines = Get-CMBaseline -WarningAction SilentlyContinue
$usedCI_IDs = $baselines.CIRelation | ForEach-Object { $_.CI_ID } | Select-Object -Unique
$unusedApps = @()

foreach ( $a in $apps ) {
    $name = $a.LocalizedDisplayName
    $ci = $a.CI_UniqueID
    $id = $a.CI_ID

    $isDeployed = $deployedApps -contains $name
    $inTS = $tsList | Where-Object { ( [xml]$_.Sequence ).InnerXml -match $ci }
    $inBaseline = $usedCI_IDs -contains $app.CI_ID
    $inCI = (Get-CMConfigurationItem -WarningAction SilentlyContinue | Where-Object { $_.References -contains $id }).Count -gt 0

    if  (-not $isDeployed -and -not $inTS -and -not $inBaseline -and -not $inCI ) {
        $folderPath = (Get-CMFolder -FolderType Application | Where-Object {
            $_.ContainerNodeID -eq $a.ContainerNodeNodeID
        }).Path
        $unusedApps += [PSCustomObject]@{
            ApplicationName = $name
            CI_ID           = $id
            FolderPath      = $folderPath
        }
    }
}
Export-Unused -Objects $unusedApps -TypeName "Unused_Applications"

# 2. Unused Device Collections (no members + no deployments)
$deviceCollections = Get-CMDeviceCollection
$deviceLimitingIDs = $deviceCollections | Select-Object -ExpandProperty LimitToCollectionID


$unusedDeviceCollections = foreach ($col in $deviceCollections) {
    if (
        ($col.MemberCount -eq 0) -and
        (-not (Get-CMDeployment -CollectionName $col.Name)) -and
        (-not $col.IsBuiltIn) -and
        ($deviceLimitingIDs -notcontains $col.CollectionID)
    ) {
        $folderPath = (Get-CMFolder -FolderType Collection -CollectionType Device | Where-Object {
            $_.ContainerNodeID -eq $col.ContainerNodeID
        }).Path

        [PSCustomObject]@{
            Name                 = $col.Name
            CollectionID         = $col.CollectionID
            MemberCount          = $col.MemberCount
            LimitingCollection   = $col.LimitToCollectionName
            FolderPath           = $folderPath
        }
    }
}
Export-Unused -Objects $unusedDeviceCollections -TypeName "Unused_Device_Collections"

# 3. Expired Deployments
$expiredDeployments = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object {
    $_.Schedule.EndTime -lt ( Get-Date )
} | ForEach-Object {
    $folderPath = (Get-CMFolder -FolderType Deployment | Where-Object {
        $_.ContainerNodeID -eq $_.ContainerNodeID
    }).Path

    $_ | Add-Member -MemberType NoteProperty -Name FolderPath -Value $folderPath -PassThru
}
Export-Unused -Objects $expiredDeployments -TypeName "Expired_Deployments"

# 4. Unused Task Sequences (not deployed)
$deployedTS = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "TaskSequence" } | Select-Object PackageName
$unusedTS = Get-CMTaskSequence -WarningAction SilentlyContinue | Where-Object { $deployedTS -notcontains $_.Name
} | ForEach-Object {
        $folderPath = (Get-CMFolder -FolderType TaskSequence | Where-Object {
            $_.ContainerNodeID -eq $_.ContainerNodeID
        }).Path

        $_ | Add-Member -MemberType NoteProperty -Name FolderPath -Value $folderPath -PassThru
    }
Export-Unused -Objects $unusedTS -TypeName "Unused_TaskSequences"

# 5. Unused Configuration Items (no deployment, not in baseline)
$allCI = Get-CMConfigurationItem -WarningAction SilentlyContinue
$usedCIs = @()
foreach ($baseline in $baselines) {
    $usedCIs += $baseline.CIRelation
}
$usedCIIDs = $usedCIs | Select-Object -ExpandProperty CI_ID -Unique
$unusedCIs = $allCI | Where-Object { $usedCIIDs -notcontains $_.CI_ID
} | ForEach-Object {
    $folderPath = (Get-CMFolder -FolderType ConfigurationItem | Where-Object {
        $_.ContainerNodeID -eq $_.ContainerNodeID
    }).Path

    $_ | Add-Member -MemberType NoteProperty -Name FolderPath -Value $folderPath -PassThru
}
Export-Unused -Objects $unusedCIs -TypeName "Unused_ConfigurationItems"

# 6. Unused Configuration Baselines (not deployed)
$deployedBaselines = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "ConfigurationBaseline" } | Select-Object -ExpandProperty SoftwareName
$unusedBaselines = $baselines | Where-Object { $deployedBaselines -notcontains $_.LocalizedDisplayName
} | ForEach-Object {
    $folderPath = (Get-CMFolder -FolderType ConfigurationBaseline | Where-Object {
        $_.ContainerNodeID -eq $_.ContainerNodeID
    }).Path

    $_ | Add-Member -MemberType NoteProperty -Name FolderPath -Value $folderPath -PassThru
}
Export-Unused -Objects $unusedBaselines -TypeName "Unused_ConfigurationBaselines"

Write-Host "All exports complete. Files saved to: $exportPath"

## --------------------------------------------------------------------------------------------------------------------------

## --------------------------------------------------------------------------------------------------------------------------

## --------------------------------------------------------------------------------------------------------------------------




Write-Host "All exports complete. Files saved to: $exportPath"