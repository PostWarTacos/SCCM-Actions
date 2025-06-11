<#
#   Intent: Get the SMS site code of the current domain when the current company doesn't have CCM installed.
#   Date: 6-Apr-25
#   Author: Matthew Wurtz
#>
function Get-SMSCode{
    # Get domain DN
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = "LDAP://CN=System Management,CN=System,DC=" + ($domain.Name -replace '\.', ',DC=')

    # Set up searcher
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$domainDN)
    $searcher.Filter = "(objectClass=mSSMSSite)"
    $searcher.SearchScope = "OneLevel"
    $searcher.PropertiesToLoad.Add("mSSMSSiteCode") | Out-Null

    # Search and print
    $results = $searcher.FindAll()
    foreach ($result in $results) {
        $code = $result.Properties["mSSMSSiteCode"]
    } 

    return $code
}

Get-SMSCode