<#
.SYNOPSIS
    Detects if the current user is added to the security policy: SeInteractiveLogonRight. 
    If the user is not added the script will add the user to the Allow logon locally' security policy.  
    The script is designed to be run as a detection and remediation script in Microsoft Intune.   
    
.DESCRIPTION
    Same as synopsis.

.NOTES
    Filename: Detect-Remediate-LockToUser.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINK
    https://www.imab.dk/configure-allow-logon-locally-automatically-using-powershell-and-microsoft-intune/    
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
    function Get-LoggedOnUsers() {
        try {
            $loggedOnUser = (Get-Process -Name explorer -IncludeUserName | Select-Object UserName -Unique).UserName
            if (-NOT[string]::IsNullOrEmpty($loggedOnUser)) {
                Write-Output $loggedOnUser
            }
            else {
                $null = $loggedOnUser
            }
        }
        catch { 
            Write-Output "[ERROR] Failed to retrieve the username of the logged on user: $_"
        }
    }
    function Get-AccountSID() {
        param (
            [string]$commonName
        )
        try {
            $account = New-Object System.Security.Principal.NTAccount($commonName)  
            $accountSID = $account.Translate([System.Security.Principal.SecurityIdentifier])
            if (-NOT[string]::IsNullOrEmpty($accountSID)) {
                Write-Output $accountSID
            }
            else {
                $null = $accountSID
            }
        }
        catch {
            Write-Output "[ERROR] Failed to retrieve the SID of the user: $_"
        }
    }
    function Get-SeInterActiveLogonRightConfig() {
        try {
            secedit.exe /export /cfg $global:tmpFile | Out-Null
            $currentConfig = (Get-Content $global:tmpFile) -like "SeInterActiveLogonRight*"
            if (-NOT[string]::IsNullOrEmpty($currentConfig)) {
                Write-Output $currentConfig
            }
            else {
                $null = $currentConfig
            }
        }
        catch {
            Write-Output "[ERROR] Failed to retrieve the current configuration of SeInteractiveLogonRight: $_"
        }
    }
    function Set-SeInterActiveLogonRightConfig() {
        param (
            [string]$currentConfig,
            [string]$newConfig
        )
        try {
            (Get-Content $global:tmpFile).Replace($currentConfig,$newConfig) | Set-Content $global:tmpFile
            secedit.exe /configure /db secedit.sdb /cfg $global:tmpFile /areas USER_RIGHTS
            Remove-Item -Path $global:tmpFile
            $global:remediationSuccess += $true
        }
        catch {
            Write-Output "[ERROR] Failed to set the new configuration of SeInteractiveLogonRight: $_"
        }
    }
    if ($runDetection -eq $false) {
        Write-Output "[ERROR] runDetection cannot be set to false. As a minimum runDetection must be set to true."
        exit 1
    }
}
process {
    $global:tmpFile = "$env:windir\Temp\secedit.tmp"
    $global:needsRemediation = @()
    $global:remediationSuccess = @()
    $loggedonUserSID = @()
    $loggedOnUsers = Get-LoggedOnUsers
    $trustedGroup = Get-AccountSID -commonName "YourDomain\Trusted Group"
    if (-NOT[string]::IsNullOrEmpty($loggedOnUsers)) {
        if ($runDetection -eq $true) {
            $currentConfig = Get-SeInterActiveLogonRightConfig
            $trimCurrentConfig = $currentConfig -split "," | ForEach-Object { $_ -replace "SeInteractiveLogonRight = " }
            foreach ($loggedOnUser in $loggedOnUsers) {
                $loggedonUserSID += Get-AccountSID -commonName $loggedOnUser
            }
            foreach ($userSID in $loggedonUserSID) {
                if ($trimCurrentConfig -notcontains "*$($userSID)") {
                    Write-Output "[WARNING] the user's SID: $userSID is NOT added to the security policy: SeInteractiveLogonRight"  
                    $global:needsRemediation += $true
                }
                elseif ($trimCurrentConfig -contains "*$($userSID)") {
                    Write-Output "[OK] the user's SID: $userSID is already added to the security policy: SeInteractiveLogonRight"
                    $global:needsRemediation += $false
                }
            }
        }
        if ($runRemediation -eq $true) {
            if ($global:needsRemediation -contains $true) {
                $newConfig = "SeInteractiveLogonRight = *S-1-5-32-544,*$($trustedGroup.Value)"
                foreach ($sid in $loggedonUserSID) {
                    $newConfig += ",*$($sid.Value)"
                }
                Set-SeInterActiveLogonRightConfig -currentConfig $currentConfig -newConfig $newConfig
            }
        }
    }
    else {
        Write-Output "[ERROR] No users are currenttly logged on to the computer."
        exit 1
    }
}
end {
    if ($runDetection -eq $true) {
        if ($global:needsRemediation -contains $true -AND $global:remediationSuccess -notcontains $true) {
            Write-Output "[WARNING] Config of the security policy: SeInteractiveLogonRight is not as expected. Remediation is needed."
            exit 1
        }
        elseif ($global:remediationSuccess -contains $true -AND $global:remediationSuccess -notcontains $false) {
            Write-Output "[OK] Remediation was run successfully. Config of the security policy: SeInteractiveLogonRight is now as expected"
            exit 0
        }
        else {
            Write-Output "[OK] Config of the security policy: SeInteractiveLogonRight is as expected. Doing nothing."
            exit 0
        }
    }
}
