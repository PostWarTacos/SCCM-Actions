$myPath = "\\LCANB-BEST2XWWY\c$\users\wurtzmt\documents"
$target = 'WCANT-FASTJ69PF'

# from ccmsetup.log with errors
Get-Content "\\$($target)\C$\Windows\ccmsetup\Logs\ccmsetup.log" | Select-String -Pattern "error|fail|unable|exitcode" -Context 5,5 > $mypath\errors_ccmsetup.log

# Get MSI log errors (may be large - adjust path if needed)
Get-Content "\\$($target)\C$\Windows\ccmsetup\Logs\client.msi.log" | Select-String -Pattern "error|return value|CustomAction.*returned|failed|return value 3" -Context 5,5 > $mypath\errors_client_msi.log

# Get WMI compilation errors specifically
Get-Content "\\$($target)\C$\Windows\ccmsetup\Logs\*.log" | Select-String -Pattern "MOF|80041002|WMI.*fail" -Context 5,5 > $mypath\errors_wmi.log

Get-Content "\\$($target)\C$\Drivers\ccm\logs\HealthCheck.txt" > $mypath\HealthCheck.txt