<#
.SYNOPSIS
    This script is intended to be used with Proactive Remediations in Microsoft Intune. This is the remediation script.
    This script kicks off, if the Detect-WindowsFirewallLogFiles.ps1 is exiting with error code 1.
    This script will create the log files for each firewall profile if they do not exist. If the log files are not configured the correct permissions, the script will recreate them with the proper permissions.

.DESCRIPTION
    Same as above

.NOTES
    Filename: Remediate-WindowsFirewallLogFiles.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINK
    https://www.imab.dk/getting-windows-11-cis-compliant-configuring-windows-firewall-logging-using-powershell-and-microsoft-intune
#> 

function New-WindowsFirewallLogFile() {
    param([string]$fileName)
    New-Item $FileName -Type File -Force -ErrorAction SilentlyContinue
    $Acl = Get-Acl $FileName
    $Acl.SetAccessRuleProtection($True,$False)
    $PermittedUsers = @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators','BUILTIN\Network Configuration Operators','NT SERVICE\MpsSvc')
    foreach ($PermittedUser in $PermittedUsers) {
        $Permission = $PermittedUser,'FullControl','Allow'
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
        $Acl.AddAccessRule($AccessRule)
    }
    $Acl.SetOwner((New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')))
    $Acl | Set-Acl $FileName 
}
try {
    New-WindowsFirewallLogFile -fileName "C:\Windows\System32\LogFiles\firewall\domainfw.log"
    New-WindowsFirewallLogFile -fileName 'C:\Windows\System32\LogFiles\firewall\domainfw.log.old'
    New-WindowsFirewallLogFile -fileName 'C:\Windows\System32\LogFiles\firewall\privatefw.log'
    New-WindowsFirewallLogFile -fileName 'C:\Windows\System32\LogFiles\firewall\privatefw.log.old'
    New-WindowsFirewallLogFile -fileName 'C:\Windows\System32\LogFiles\firewall\publicfw.log'
    New-WindowsFirewallLogFile -fileName 'C:\Windows\System32\LogFiles\firewall\publicfw.log.old'
    Write-Output "[All good]. Remediation script is done running"
    exit 0
}
catch {
    Write-Output "[Not good]. Something went horribly wrong when running the remediation script. Please investigate"
    exit 1
}