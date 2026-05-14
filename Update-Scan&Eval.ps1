([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}');
(New-Object -ComObject Microsoft.CCM.UpdatesStore).RefreshServerComplianceState();
wuauclt.exe /ResetAuthorization /DetectNow;
wuauclt /reportnow
 System.Management.ManagementBaseObject; "Update Scan"
