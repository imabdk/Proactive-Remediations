<#
.SYNOPSIS
    This script is intended to be used with Proactive Remediations in Microsoft Intune. This is the remediation script.
    This script will configure logging for all 3 firewall profiles according to CIS recommendations.
    The logging path will be set to a specific path, the log size to 16384KB and enable logging for allowed and blocked packages

.DESCRIPTION
    Same as above

.NOTES
    Filename: Detect-WindowsFirewallLogFiles.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINK
    https://www.imab.dk/getting-windows-11-cis-compliant-configuring-windows-firewall-logging-using-powershell-and-microsoft-intune
    
#> 

function Set-WindowsFirewallLogging() {
    [CmdletBinding()]
    param(
        [ValidateSet("Domain","Private","Public")]
        [string]$profileName,
        [string]$logFileName,
        [string]$logSize,
        [ValidateSet("True","False")]
        [string]$logAllowed,
        [ValidateSet("True","False")]
        [string]$logBlocked
    )
    $currentProfile = Get-NetFirewallProfile -Name $profileName
    if ($currentProfile.LogFileName -ne $logFileName) {
        Set-NetFirewallProfile -Name $profileName -LogFileName $logFileName
    }
    if ($currentProfile.LogMaxSizeKilobytes -ne $logSize) {
        Set-NetFirewallProfile -Name $profileName -LogMaxSizeKilobytes $logSize
    }
    if ($currentProfile.LogAllowed -ne $logAllowed) {
        Set-NetFirewallProfile -Name $profileName -LogAllowed $logAllowed
    }
    if ($currentProfile.LogBlocked -ne $logBlocked) {
        Set-NetFirewallProfile -Name $profileName -LogBlocked $logBlocked
    }
}
try {
    Set-WindowsFirewallLogging -profileName Domain -logFileName C:\Windows\system32\logfiles\firewall\domainfw.log -logSize 16384 -logAllowed True -logBlocked True
    Set-WindowsFirewallLogging -profileName Private -logFileName C:\Windows\system32\logfiles\firewall\privatefw.log -logSize 16384 -logAllowed True -logBlocked True
    Set-WindowsFirewallLogging -profileName Public -logFileName C:\Windows\system32\logfiles\firewall\publicfw.log -logSize 16384 -logAllowed True -logBlocked True
    Write-Output "[All good]. Remediation script is done running"
    exit 0
}
catch {
    Write-Output "[Not good]. Something went horribly wrong when running the remediation script. Please investigate"
    exit 1
}