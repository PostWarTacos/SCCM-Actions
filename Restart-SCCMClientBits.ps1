<#
.Synopsis
    Write-CMLog writes a message to a specified log file in the CMTrace formatting.

.DESCRIPTION
    The Write-CMLog function is designed to add logging capability to other scripts.
    This enables scripters to easily add logging to their scripts in the famous CMTrace
    formatting, making logging uniform and consistant. 

.NOTES
    This was created by Cameron Cox, leveraging a combination of ideas and code from
    funciton Write-Log created by Jason Wasser @wasserja, and the Module Write-CMTrace
    created by Syliance IT Services GmbH.

    Created by: Cameron Cox 
    Created On: 10-26-2016
    Twitter Handle: @Drummer_Cameron 
    Blog: https://blogs.technet.microsoft.com/systemcenterpfe/

    I am a Microsoft Premier Field Engieer, focusing on Configuration Manger, 
    Automation, PowerShell and Microsoft Bitlocker Administrator and Monitoring aka MBAM. 

.PARAMETER Message
    The -Message parameter is required unless you use the -ErrorMessage Parameter or -WarnMessage.
    The value passed to this parameter will be written to the LogText column in CMTrace.
    By default, this parameter sets the -Type to 1 (Informational), this still can be set
    by using the -Type parameter.

.PARAMETER ErrorMessage
    The -ErrorMessage parameter is required unless you use the -Message Parameter or -WarnMessage.
    The value passed to this parameter will be written to the LogText column in CMTrace.
    By default, this parameter sets the -Type to 3 (Error), this still can be set
    by using the -Type parameter.

.PARAMETER WarnMessage
    The -WarnMessage parameter is required unless you use the -Message Parameter or -ErrorMessage.
    The value passed to this parameter will be written to the LogText column in CMTrace.
    By default, this parameter sets the -Type to 2 (Warning), this still can be set
    by using the -Type parameter.

.PARAMETER Path
    The -Path variable determines the location and name of the log. By default the function will 
    create the path and file if it does not exist. If the -Path variable is not specified, the 
    function writes the log to the defauly location. (%SystemDrive%\Windows\Sytem32\Logfiles\<YourScriptName>.log).

.PARAMETER Component
     The -Component alows you to specify a fuction or section in your script, helping you identify messages
     and and the relative location where the messages are being generated from. 
  
.PARAMETER Type
    The -Type parameter specifies the level of messages,1 = Informational, 2 = Warning (yellow), 3 = Error (red).

.PARAMETER Thread
    This by default will pull in the current process ID of the running script. If you wish to override
    with a different process ID, you can leverage the Get-Process command and pull in the ID object, as 
    shown in a example below.

.PARAMETER NoClobber
    Use NoClobber if you do not wish to overwrite an existing file.

.EXAMPLE
    Write-CMLog -M "Hellow World" -Path .\Desktop\Test.log -Component TST_Func

.EXAMPLE
    Write-CMLog -Message "Some Error Message" -Component SomthingHere -Type 3 

.EXAMPLE
    LOG -Message "This is l33t $p3@k" -Path .\leet.log -Type 2

.EXAMPLE 
    LOG -ErrorMessage "Some Error Message" -Path .\Desktop\Test$(Get-Date -Format MM-dd-yyy).log 

.EXAMPLE 
    LOG -ErrorMessage "Hellow World" -Path .\Desktop\Test$(Get-Date -Format MM-dd-yyy).log -Comp "Start Services"

.EXAMPLE 
    Write-CMLog -EM "Testing" -Path .\Desktop\Test$(Get-Date -Format MM-dd-yyy).log -Component Some_Function -Level 2

.EXAMPLE 
    LOG -WM "Testing" -Path .\Desktop\Test.log 

.EXAMPLE 
    LOG -WarnMessage "Testing" -Path .\Desktop\Test.log -Component Configuring_Services

.EXAMPLE 
    LOG -WarnMessage "Testing" -Path .\Desktop\Test.log -Type 1

.EXAMPLE
    Write-CMLog -ErrorMessage "Some Error Message" -Path .\Desktop\Test.log -Component Test -Type 2 -Thread (Get-Process -Name cmtrace).ID

.LINKS
    Write-CMLog

.LINKS
    Write-Log https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0

.LINKS
    Write-CMTrace - https://gallery.technet.microsoft.com/Write-CMTrace-0330216e
#>
function Write-CMLog
{
    [CmdletBinding(DefaultParameterSetName="Message")]
    [Alias('LOG')]
    Param
    (
        [Parameter(Mandatory=$true, ParameterSetName="Message")]
        [ValidateNotNull()]
        [Alias("M")]
        $Message,

        [Parameter(Mandatory=$true, ParameterSetName="ErrorMessage")]
        [ValidateNotNull()]
        [Alias("EM")]
		$ErrorMessage,

        [Parameter(Mandatory=$true, ParameterSetName="WarnMessage")]
        [ValidateNotNull()]
        [Alias("WM")]
		$WarnMessage,

        [Parameter(Mandatory=$false, ParameterSetName="Message")] 
        [Parameter(ParameterSetName="ErrorMessage")]
        [Parameter(ParameterSetName="WarnMessage")]
        [Alias("LogPath")]
        [string]$Path = "C:\Windows\System32\LogFiles\$($MyInvocation.MyCommand.Name).log",

		[Parameter(Mandatory=$false, ParameterSetName="Message")] 
        [Parameter(ParameterSetName="ErrorMessage")]
        [Parameter(ParameterSetName="WarnMessage")]
        [Alias("Comp")]
		$Component = $($MyInvocation.MyCommand.Name),

		[Parameter(Mandatory=$false, ParameterSetName="Message")]
        [Parameter(ParameterSetName="ErrorMessage")]
        [Parameter(ParameterSetName="WarnMessage")]
        [Alias("Level")]
        [ValidateSet(1, 2, 3)]
		[int]$Type = $(IF ($Message) {1} ELSEIF ($ErrorMessage) {3} ELSE {2}),

		[Parameter(Mandatory=$false, ParameterSetName="Message")]
        [Parameter(ParameterSetName="ErrorMessage")]
        [Parameter(ParameterSetName="WarnMessage")]
		$Thread = $PID,

		[Parameter(Mandatory=$false, ParameterSetName="Message")]
        [Parameter(ParameterSetName="ErrorMessage")]
        [Parameter(ParameterSetName="WarnMessage")]
        [switch]$NoClobber
    )

    Begin
    {
        $Time = Get-Date -Format "HH:mm:ss.ffffff"
	    $Date = Get-Date -Format "MM-dd-yyyy"
    }
    Process
    {
        # If the file already exists and NoClobber was specified, do not write to the log.
        IF ((Test-Path $Path) -AND $NoClobber) 
        {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        ELSEIF (!(Test-Path $Path)) 
        {
            $NewLogFile = New-Item $Path -Force -ItemType File
            $LogMessage = "<![LOG[Creating File - $NewLogFile" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"Write-CMLog`" context=`"New File`" type=`"1`" thread=`"$Thread`" file=`"$($MyInvocation.MyCommand.Name)`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $Path
        }

        ELSE 
        {
            #Do Nothing
        }
        


        ## Logging
        $LogMessage = "<![LOG[$Message$ErrorMessage$WarnMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"$Context`" type=`"$Type`" thread=`"$Thread`" file=`"$($MyInvocation.MyCommand.Name)`">"

        ## Write the Log
        $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $Path
    }
    End
    {
    }

}

<#
#This Sample Code is provided for the purpose of illustration only
#and is not intended to be used in a production environment.  THIS
#SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
#WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
#LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
#FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
#right to use and modify the Sample Code and to reproduce and distribute
#the object code form of the Sample Code, provided that You agree:
#(i) to not use Our name, logo, or trademarks to market Your software
#product in which the Sample Code is embedded; (ii) to include a valid
#copyright notice on Your software product in which the Sample Code is
#embedded; and (iii) to indemnify, hold harmless, and defend Us and
#Our suppliers from and against any claims or lawsuits, including
#attorneys' fees, that arise or result from the use or distribution
#of the Sample Code.
#>

$CCMSetupLog = "$ENV:SystemDrive\Windows\Temp\Remove-SCCMClientBits.log"
Write-CMLog -Message "Starting the ConfigMgr Client Uninstall" -Path $CCMSetupLog

Stop-Service CcmExec -Force -ErrorVariable Stop_Error -OutVariable Stop
IF ($Stop) {Write-CMLog -Message $Stop -Path $CCMSetupLog -Component Stopping_CCMExec}
IF ($Stop_Error) {Write-CMLog -EM $Stop_Error -Path $CCMSetupLog -Component Stopping_CCMExec}

Invoke-Command { CMD /C "$ENV:SystemDrive\Windows\ccmsetup\ccmsetup.exe /UNINSTALL" }
DO
{
    Write-Host "Waiting for the ConfigMgr Client to uninstall"
    Start-Sleep 5

}
WHILE(Get-Process -Name ccmsetup) 

$Lines = (Get-Content -Path $ENV:SystemDrive\Windows\ccmsetup\logs\ccmsetup.log | Measure-Object).Count - 1
$SetupLogReturn =  (Get-Content -Path $ENV:SystemDrive\Windows\ccmsetup\logs\ccmsetup.log)[$Lines]

If ($SetupLogReturn -like "*return code 0*") {$Type = 1} ELSE {$Type = 3}

Write-CMLog -Message "$SetupLogReturn" -Path $CCMSetupLog -Component SMS_Uninstall -Type $Type

##
## Removing File/Folder Bits
IF (Test-Path -Path $ENV:SystemDrive\windows\ccm) { Remove-Item -Path $ENV:SystemDrive\windows\ccm -Force -Recurse -Verbose -OutVariable CCM_Remove -ErrorVariable CCM_Remove_Error -ErrorAction SilentlyContinue}
IF ($CCM_Remove) { Write-CMLog -Message "Removing $ENV:SystemDrive\windows\ccm - $CCM_Remove" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF ($CCM_Remove_Error) { Write-CMLog -EM "Error Removing $ENV:SystemDrive\windows\ccm - $CCM_Remove" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF (Test-Path -Path $ENV:SystemDrive\windows\ccmsetup) { Remove-Item -Path $ENV:SystemDrive\windows\ccmsetup -Force -Recurse -Verbose -OutVariable CCM_Remove2 -ErrorVariable CCM_Remove_Error2 -ErrorAction SilentlyContinue }
IF ($CCM_Remove2) { Write-CMLog -Message "Removing $ENV:SystemDrive\windows\ccmsetup - $CCM_Remove2" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF ($CCM_Remove_Error2) { Write-CMLog -EM "Error Removing $ENV:SystemDrive\windows\ccmsetup - $CCM_Remove_Error2" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF (Test-Path -Path $ENV:SystemDrive\windows\ccmcache) { Remove-Item -Path $ENV:SystemDrive\windows\ccmcache -Force -Recurse -Verbose -OutVariable CCM_Remove3 -ErrorVariable CCM_Remove_Error3 -ErrorAction SilentlyContinue }
IF ($CCM_Remove3) { Write-CMLog -Message "Removing $ENV:SystemDrive\windows\ccmcache - $CCM_Remove3" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF ($CCM_Remove_Error3) { Write-CMLog -EM "Error Removing $ENV:SystemDrive\windows\ccmcache - $CCM_Remove_Error3" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF (Test-Path -Path $ENV:SystemDrive\windows\smscfg.ini) { Remove-Item -Path $ENV:SystemDrive\windows\smscfg.ini -Force -Recurse -Verbose -OutVariable CCM_Remove4 -ErrorVariable CCM_Remove_Error4 -ErrorAction SilentlyContinue }
IF ($CCM_Remove4) { Write-CMLog -Message "Removing $ENV:SystemDrive\windows\smscfg.ini - $CCM_Remove4" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF ($CCM_Remove_Error4) { Write-CMLog -EM "Error Removing $ENV:SystemDrive\windows\smscfg.ini - $CCM_Remove_Error4" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF (Test-Path -Path $ENV:SystemDrive\windows\sms*.mif) { Remove-Item -Path $ENV:SystemDrive\windows\sms*.mif -Force -Recurse -Verbose -OutVariable CCM_Remove5 -ErrorVariable CCM_Remove_Error5 -ErrorAction SilentlyContinue }
IF ($CCM_Remove5) { Write-CMLog -Message "Removing $ENV:SystemDrive\windows\sms*.mif - $CCM_Remove5" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF ($CCM_Remove_Error5) { Write-CMLog -EM "Error Removing $ENV:SystemDrive\windows\sms*.mif - $CCM_Remove_Error5" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF (Test-Path -Path $ENV:SystemDrive\windows\smsts.ini) { Remove-Item -Path $ENV:SystemDrive\windows\smsts.ini -Force -Recurse -Verbose -OutVariable CCM_Remove6 -ErrorVariable CCM_Remove_Error6 -ErrorAction SilentlyContinue }
IF ($CCM_Remove6) { Write-CMLog -Message "Removing $ENV:SystemDrive\windows\smsts.ini - $CCM_Remove6" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}
IF ($CCM_Remove_Error6) { Write-CMLog -EM "Error Removing $ENV:SystemDrive\windows\smsts.ini - $CCM_Remove_Error6" -Path $CCMSetupLog -Component "Removing File/Folder Bits"}


##
## Removing Registry Bits
IF (Test-Path -Path HKLM:\software\Microsoft\ccm) { Remove-Item -Path HKLM:\software\Microsoft\ccm  -Force -Recurse -OutVariable RemoveHKLM -ErrorVariable RemoveHKLM_Error -ErrorAction SilentlyContinue }
IF ($RemoveHKLM) { Write-CMLog -Message "Removing HKLM:\software\Microsoft\ccm  - $RemoveHKLM" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF ($RemoveHKLM_Error) { Write-CMLog -EM "Error Removing HKLM:\software\Microsoft\ccm  - $RemoveHKLM_Error" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF (Test-Path -Path HKLM:\software\Microsoft\CCMSETUP) { Remove-Item -Path HKLM:\software\Microsoft\CCMSETUP  -Force -Recurse -OutVariable RemoveHKLM2 -ErrorVariable RemoveHKLM_Error2 -ErrorAction SilentlyContinue }
IF ($RemoveHKLM2) { Write-CMLog -Message "Removing HKLM:\software\Microsoft\CCMSETUP - $RemoveHKLM2" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF ($RemoveHKLM_Error2) { Write-CMLog -EM "Error Removing HKLM:\software\Microsoft\CCMSETUP - $RemoveHKLM_Error2" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF (Test-Path -Path HKLM:\software\Microsoft\SMS) { Remove-Item -Path HKLM:\software\Microsoft\SMS  -Force -Recurse -OutVariable RemoveHKLM3 -ErrorVariable RemoveHKLM_Error3 -ErrorAction SilentlyContinue } 
IF ($RemoveHKLM3) { Write-CMLog -Message "Removing HKLM:\software\Microsoft\SMS - $RemoveHKLM3" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF ($RemoveHKLM_Error3) { Write-CMLog -EM "Error Removing HKLM:\software\Microsoft\SMS - $RemoveHKLM_Error3" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF (Test-Path -Path HKLM:\software\Microsoft\Systemcertificates\SMS\Certificates) { Remove-Item -Path HKLM:\software\Microsoft\Systemcertificates\SMS\Certificates -Force -Recurse -OutVariable RemoveHKLM4 -ErrorVariable RemoveHKLM_Error4 -ErrorAction SilentlyContinue }
IF ($RemoveHKLM4) { Write-CMLog -Message "Removing HKLM:\software\Microsoft\Systemcertificates\SMS\Certificates - $RemoveHKLM4" -Path $CCMSetupLog -Component "Removing Registry Bits"}
IF ($RemoveHKLM_Error4) { Write-CMLog -EM "Error Removing HKLM:\software\Microsoft\Systemcertificates\SMS\Certificates - $RemoveHKLM_Error4" -Path $CCMSetupLog -Component "Removing Registry Bits"}
##
## Removing WMI Bits
Get-WmiObject -Namespace Root\cimv2\sms -List * -OutVariable +Remove_WMI -ErrorVariable +Remove_WMI_Error -ErrorAction SilentlyContinue | FOREACH { Remove-WmiObject -Namespace Root\cimv2\sms -Class $_.Name -OutVariable +Remove_WMI -ErrorVariable +Remove_WMI_Error -ErrorAction SilentlyContinue }
Get-WmiObject -Namespace Root\ccm -List * -OutVariable +Remove_WMI -ErrorVariable +Remove_WMI_Error -ErrorAction SilentlyContinue | FOREACH { Remove-WmiObject -Namespace Root\ccm -Class $_.Name -OutVariable +Remove_WMI -ErrorVariable +Remove_WMI_Error -ErrorAction SilentlyContinue }

IF ($Remove_WMI) { $Remove_WMI | FOREACH { Write-CMLog -Message "Removing - $Remove_WMI" -Path $CCMSetupLog -Component "Removing WMI Bits" } }
IF ($Remove_WMI_Error) { $Remove_WMI_Error | FOREACH { Write-CMLog -EM "Removing - $Remove_WMI_Error" -Path $CCMSetupLog -Component "Removing WMI Bits" } }