#######################################Rerun Task Sequence
$TaskSequenceName = 'TS - Tenable Agent - PROD'
# Retrieve the PackageID and AdvertisementID from the machine actual policy
$SoftwareDistributionPolicy = Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_SoftwareDistribution" | Where-Object { $_.PKG_Name -match $TaskSequenceName } | Select-Object -ExpandProperty PKG_PackageID
# Set Registry Path to Search
$Key = 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\Execution History\System'
# Clean TS
Get-ChildItem $Key -Recurse -EA SilentlyContinue | ForEach-Object {
$CurrentKey = (Get-ItemProperty -Path $_.PsPath)
    
    If ($CurrentKey -match $SoftwareDistributionPolicy) {
        $CurrentKey
        $CurrentKey | Remove-Item -Force -Recurse
        $CurrentKey.PSParentPath 
        }
    }
# Run TS
$ScheduleID = Get-WmiObject -Namespace "root\ccm\scheduler" -Class "CCM_Scheduler_History" | Where-Object { $_.ScheduleID -like "*$($SoftwareDistributionPolicy)*" } | Select-Object -ExpandProperty ScheduleID
Invoke-command {([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule($ScheduleID)}