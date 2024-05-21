<#
.SYNOPSIS
    This script is used to detect and remediate built-in apps in Windows 11.

.DESCRIPTION
    The script provides two main functionalities: detection and remediation of built-in apps. By default, the script runs in detection mode, but it can also be configured to perform remediation.
    The list of built-in apps to be detected and remediated can be customized by modifying the $appxPackageList array in the script.

.NOTES
    File Name      : Detect-Remediate-Windows-11-Built-In-Apps.ps1
    Author         : Martin Bengtsson
    Blog           : https://www.imab.dk
#>

param (
    [bool]$runDetection = $true,
    [bool]$runRemediation = $true
)

begin {
    $appxPackageList = @(
        "MicrosoftCorporationII.QuickAssist"
        "MicrosoftTeams"
    )
    function Test-InstalledAppxPackages() {
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
            Write-Output "[OK] Remediation was run successfully. Built-in apps were removed."
            exit 0
        }
        else {
            Write-Output "[OK] No built-in apps found. Doing nothing."
            exit 0
        }
    }
}
