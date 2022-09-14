<#
.SYNOPSIS
    This script is intended to be used with Proactive Remediations in Microsoft Intune. This is the detection script.
    This script detects if each firewall profile is configured to enable logging according to CIS recommendations.
    If any of the 3 profiles is not configured accordingly, the script will exit with error code 1, instructing the remediation script to kick off.

.DESCRIPTION
    Same as above

.NOTES
    Filename: Detect-WindowsFirewallLogging.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINK
    https://www.imab.dk/getting-windows-11-cis-compliant-configuring-windows-firewall-logging-using-powershell-and-microsoft-intune
    
#> 

function Get-WindowsFirewallLogging() {
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
        Write-Output "[Not good]. $($currentProfile.LogFileName) is not equal to logFileName: $logFileName. Needs remediation"
        $global:needsRemediation = $true
    }
    if ($currentProfile.LogMaxSizeKilobytes -ne $logSize) {
        Write-Output "[Not good]. $($currentProfile.LogMaxSizeKilobytes) is not equal to logSize: $logSize. Needs remediation"
        $global:needsRemediation = $true
    }
    if ($currentProfile.LogAllowed -ne $logAllowed) {
        Write-Output "[Not good]. $($currentProfile.LogAllowed) is not equal to logAllowed: $logAllowed. Needs remediation"
        $global:needsRemediation = $true
    }
    if ($currentProfile.LogBlocked -ne $logBlocked) {
        Write-Output "[Not good]. $($currentProfile.LogBlocked) is not equal to logBlocked: $logBlocked. Needs remediation"
        $global:needsRemediation = $true
    }
}
try {
    Clear-Variable -Name needsRemediation -ErrorAction SilentlyContinue
    $domainfw = Get-WindowsFirewallLogging -profileName Domain -logFileName C:\Windows\system32\logfiles\firewall\domainfw.log -logSize 16384 -logAllowed True -logBlocked True
    $privatefw = Get-WindowsFirewallLogging -profileName Private -logFileName C:\Windows\system32\logfiles\firewall\privatefw.log -logSize 16384 -logAllowed True -logBlocked True
    $publicfw = Get-WindowsFirewallLogging -profileName Public -logFileName C:\Windows\system32\logfiles\firewall\publicfw.log -logSize 16384 -logAllowed True -logBlocked True
    if ($global:needsRemediation -eq $true) {
        if (($domainfw -ne $null) -OR ($privatefw -ne $null) -OR ($publicfw -ne $null)) {
            if ($domainfw -ne $null) {
                Write-Output $domainfw
                exit 1
            }
            if ($privatefw -ne $null) {
                Write-Output $privatefw
                exit 1
            }
            if ($publicfw -ne $null) {
                Write-Output $publicfw
                exit 1
            }       
        }   
    }
    else {
        Write-Output "[All good]. The detection script ran successfully without errors. Doing nothing"
        exit 0
    }
}
catch {
    Write-Output "[Not good]. Something went horribly wrong when running the detection script. Please investigate"
    exit 1
}