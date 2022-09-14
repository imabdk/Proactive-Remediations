<#
.SYNOPSIS
    This script is intended to be used with Proactive Remediations in Microsoft Intune. This is the detection script.
    This script detects if the log files for each firewall profile; domain, private and public exist with the correct permissions
    If the files do not exist or do not have the correct permissions, the script will exit with error code 1, instructing the remediation script to kick off.
        
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

function Check-WindowsFirewallLogFile() {
    param([string]$fileName)
    $requiredIdentities = "NT AUTHORITY\SYSTEM","BUILTIN\Administrators","BUILTIN\Network Configuration Operators","NT SERVICE\MpsSvc"
    $Acl = Get-Acl $fileName -ErrorAction SilentlyContinue
    if (-NOT[string]::IsNullOrEmpty($Acl)) {
        foreach ($identity in $requiredIdentities) {
            if ($identity -notin $Acl.Access.IdentityReference.Value) {
                $needsRemediation = $true
            }
            else {
                $needsRemediation = $false
            }        
        }
        if ($needsRemediation -eq $true) {
            Write-Output "[Not good]. Acl on log file: $fileName is not properly configured. Needs remediation"
        }
        elseif ($needsRemediation -eq $false) {
            Write-Output "[All good]. Acl on log file: $fileName is properly configured. Doing nothing"
        }
    }
    else {
        Write-Output "[Not good]. Log file: $fileName does not seem to exist. Needs remediation"
    }
}
try {
    $domainfw = Check-WindowsFirewallLogFile -fileName "C:\Windows\System32\LogFiles\Firewall\domainfw.log"
    $privatefw = Check-WindowsFirewallLogFile -fileName "C:\Windows\System32\LogFiles\Firewall\privatefw.log"
    $publicfw = Check-WindowsFirewallLogFile -fileName "C:\Windows\System32\LogFiles\Firewall\publicfw.log"
    if ($domainfw.StartsWith("[Not good]") -OR $privatefw.StartsWith("[Not good]") -OR $publicfw.StartsWith("[Not good]")) {
        if ($domainfw.StartsWith("[Not good]") -eq $true) {
            Write-Output $domainfw
            exit 1
        }
        if ($privatefw.StartsWith("[Not good]") -eq $true) {
            Write-Output $privatefw
            exit 1
        }
        if ($publicfw.StartsWith("[Not good]") -eq $true) {
            Write-Output $publicfw
            exit 1
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
