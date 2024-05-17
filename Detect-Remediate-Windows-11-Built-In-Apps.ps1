<#
.SYNOPSIS
    Detects and removes built-in apps in Windows 11.

.DESCRIPTION
    This script detects and removes built-in apps in Windows 11. It can be used as a detection and remediation script in Microsoft Intune.

.NOTES
    Filename: Detect-Remediate-Windows-11-Built-In-Apps.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

#>
[CmdletBinding()]
param (
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [bool]$runDetection = $true,
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [bool]$runRemediation = $true
)
begin {
    $appxPackageList = @(
        "MicrosoftCorporationII.QuickAssist"
        "MicrosoftTeams"
    )
    function Test-InstalledAppxPackages {
        foreach ($app in $appxPackageList) {
            try {
                $isAppInstalled = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
                if (-NOT[string]::IsNullOrEmpty($isAppInstalled)) {
                    Write-Output $app
                }
            }
            catch {
                Write-Output "[ERROR] Failed to retrieve the installed app: $_"
            }
        }
    }
    function Remove-InstalledAppxPackages() {
        param (
            [string]$appxPackage
        )
        try {
            Get-AppxPackage -Name $appxPackage | Remove-AppxPackage
            $global:remediationSuccess += $true
        }
        catch {
            Write-Output "[ERROR] Failed to remove the app: $_"
        }
    }
    if ($runDetection -eq $false) {
        Write-Output "[ERROR] runDetection cannot be set to false. As a minimum runDetection must be set to true."
        exit 1
    }
}
process {
    $global:needsRemediation = @()
    $global:remediationSuccess = @()
    $installedAppxPackages = Test-InstalledAppxPackages
    if ($runDetection -eq $true) {
        if (-NOT[string]::IsNullOrEmpty($installedAppxPackages)) {
            foreach ($app in $installedAppxPackages) {
                $global:needsRemediation += $true
                if ($runRemediation -eq $true) {
                    Remove-InstalledAppxPackages -appxPackage $app
                }
            }
        }
    }
}
end {
    if ($runDetection -eq $true) {
        if ($global:needsRemediation -contains $true -AND $global:remediationSuccess -notcontains $true) {
            Write-Output "[WARNING] Built-in apps found installed. Remediation is needed."
            exit 1
        }
        elseif ($global:remediationSuccess -contains $true -AND $global:remediationSuccess -notcontains $false) {
            Write-Output "[OK] Remediation was run successfully. Built-in apps was removed."
            exit 0
        }
        else {
            Write-Output "[OK] No built-in apps found. Doing nothing."
            exit 0
        }
    }
}