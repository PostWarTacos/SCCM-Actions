
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
        $unusedApps += [PSCustomObject]@{
            ApplicationName = $name
            CI_ID = $id
        }
    }
}
Export-Unused -Objects $unusedApps -TypeName "Unused_Applications"

# 2. Unused Device Collections (no members + no deployments)
$unusedDeviceCollections = Get-CMDeviceCollection -WarningAction SilentlyContinue | Where-Object {
    ( $_.MemberCount -eq 0 ) -and
    ( -not ( Get-CMDeployment -CollectionName $_.Name -WarningAction SilentlyContinue )) -and
    ( -not $_.IsBuiltIn )
}
Export-Unused -Objects $unusedDeviceCollections -TypeName "Unused_Device_Collections"

# 3. Unused User Collections
$unusedUserCollections = Get-CMUserCollection -WarningAction SilentlyContinue | Where-Object {
    ( $_.MemberCount -eq 0 ) -and
    ( -not ( Get-CMDeployment -CollectionName $_.Name  -WarningAction SilentlyContinue )) -and
    ( -not $_.IsBuiltIn )
}
Export-Unused -Objects $unusedUserCollections -TypeName "Unused_User_Collections"

# 4. Expired Deployments
$expiredDeployments = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object {
    $_.Schedule.EndTime -lt ( Get-Date )
}
Export-Unused -Objects $expiredDeployments -TypeName "Expired_Deployments"

# 5. Unused Task Sequences (not deployed)
$deployedTS = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "TaskSequence" } | Select-Object -ExpandProperty PackageName
$unusedTS = Get-CMTaskSequence -WarningAction SilentlyContinue | Where-Object {
    $deployedTS -notcontains $_.Name
}
Export-Unused -Objects $unusedTS -TypeName "Unused_TaskSequences"

# 6. Unused Configuration Items (no deployment, not in baseline)
$allCI = Get-CMConfigurationItem -WarningAction SilentlyContinue
$usedCIs = @()
foreach ($baseline in $baselines) {
    $usedCIs += $baseline.CIRelation
}
$usedCIIDs = $usedCIs | Select-Object -ExpandProperty CI_ID -Unique
$unusedCIs = $allCI | Where-Object {
    $usedCIIDs -notcontains $_.CI_ID
}
Export-Unused -Objects $unusedCIs -TypeName "Unused_ConfigurationItems"

# 7. Unused Configuration Baselines (not deployed)
$deployedBaselines = Get-CMDeployment -WarningAction SilentlyContinue | Where-Object { $_.SoftwareType -eq "ConfigurationBaseline" } | Select-Object -ExpandProperty SoftwareName
$unusedBaselines = $baselines | Where-Object {
    $deployedBaselines -notcontains $_.LocalizedDisplayName
}
Export-Unused -Objects $unusedBaselines -TypeName "Unused_ConfigurationBaselines"

Write-Host "All exports complete. Files saved to: $exportPath"
