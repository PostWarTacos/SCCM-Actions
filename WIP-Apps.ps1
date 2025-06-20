$apps = Get-CMApplication -WarningAction SilentlyContinue
$deployedApps = Get-CMApplicationDeployment -WarningAction SilentlyContinue
$tsList = Get-CMTaskSequence -WarningAction SilentlyContinue
$baselines = Get-CMBaseline -WarningAction SilentlyContinue
$ciList = Get-CMConfigurationItem -WarningAction SilentlyContinue
$cimApps = Get-CimInstance -ComputerName $siteServer -Namespace "root/SMS/site_$SiteCode" -ClassName SMS_ApplicationLatest
$unusedApps = @()
$inTS = @()
$inci = @()
$isDeployed = @()
$inBaseline = @()

foreach ( $a in $apps ) {
    $escapedModelName = [WildcardPattern]::Escape($a.ModelName)
    $escapedPackageID = [WildcardPattern]::Escape($a.PackageID)
    
    $inTS += $tsList | Where-Object {
        $_.Sequence -like "*$escapedModelName*"
    }
    
    $inCI += $ciList | Where-Object {
        $_.Sequence -like "*$escapedPackageID*"
    }

    $isDeployed += $deployedApps | Where-Object {
        $_.applicationname -contains $a.LocalizedDisplayName -and
        $_.AssignedCI_UniqueID -contains $a.CI_UniqueID
    }

    $inBaseline += $usedCI_IDs -contains $a.CI_ID

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