<#
.SYNOPSIS
This script detects and optionally removes specified built-in Appx packages from a Windows system.

.DESCRIPTION
The script checks for the presence of specified built-in Appx packages (e.g., Microsoft.OutlookForWindows) and optionally removes them if they are found. It provides options to run detection only or both detection and remediation. The script outputs the status of the detection and remediation process.

.PARAMETER runDetection
A boolean parameter that specifies whether to run the detection process. This parameter must be set to $true.

.PARAMETER runRemediation
A boolean parameter that specifies whether to run the remediation process if built-in Appx packages are detected. This parameter is optional and defaults to $true.

.EXAMPLE
.\Detect-Remediate-Uninstall-NewOutlook.ps1 -runDetection $true -runRemediation $true
Runs the script to detect and remove the specified built-in Appx packages.

.EXAMPLE
.\Detect-Remediate-Uninstall-NewOutlook.ps1 -runDetection $true -runRemediation $false
Runs the script to detect the specified built-in Appx packages without removing them.

.NOTES
    - Filename: Detect-Remediate-Uninstall-NewOutlook.ps1
    - Author: Martin Bengtsson
    - Blog: www.imab.dk
    - Twitter: @mwbengtsson
#>
param (
    [bool]$runDetection = $true,
    [bool]$runRemediation = $true
)
begin {
    $appxPackageList = @(
        "Microsoft.OutlookForWindows"
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
