<#
.SYNOPSIS
    Detects if the current user is added to the security policy: SeInteractiveLogonRight. 
    If the user is not added the script will add the user to the Allow logon locally' security policy.  
    The script is designed to be run as a detection and remediation script in Microsoft Intune.   
    
.DESCRIPTION
    This script manages the SeInteractiveLogonRight security policy to ensure currently logged-on users
    have permission to log on locally. It can run in detection-only mode or perform automatic remediation.
    
    The script:
    1. Identifies currently logged-on users
    2. Checks if they have SeInteractiveLogonRight permission
    3. Optionally adds missing users to the security policy
    4. Maintains existing permissions for built-in groups

.PARAMETER runDetection
    Whether to run the detection phase. Cannot be set to false as detection is required.
    Default: $true

.PARAMETER runRemediation  
    Whether to run the remediation phase if issues are detected.
    Default: $true

.PARAMETER trustedGroup
    The trusted group to include in the security policy. 
    Default: "DOMAIN\Local Admins Group"

.PARAMETER includeWSIAccount
    Whether to include the WSI account in the security policy.
    The account will be added as COMPUTERNAME\WsiAccount.
    Default: $true

.EXAMPLE
    .\Detect-Remediate-LockToUser.ps1
    Runs both detection and remediation with default settings.

.EXAMPLE
    .\Detect-Remediate-LockToUser.ps1 -Verbose
    Runs with verbose output for troubleshooting.

.NOTES
    Filename: Detect-Remediate-LockToUser.ps1
    Version: 1.1
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson
    
    Requirements:
    - Administrative privileges
    - Windows with secedit.exe available

.LINK
    https://www.imab.dk/configure-allow-logon-locally-automatically-using-powershell-and-microsoft-intune/
    
#> 
[CmdletBinding()]
param (
    [parameter(Mandatory=$false, HelpMessage="Whether to run the detection phase. Cannot be disabled.")]
    [ValidateNotNullOrEmpty()]
    [bool]$runDetection = $true,
    
    [parameter(Mandatory=$false, HelpMessage="Whether to run the remediation phase if issues are detected.")]
    [ValidateNotNullOrEmpty()]
    [bool]$runRemediation = $true,
    
    [parameter(Mandatory=$false, HelpMessage="The trusted group to include in the security policy.")]
    [ValidateNotNullOrEmpty()]
    [string]$trustedGroup = "DOMAIN\Local Admins Group",
    
    [parameter(Mandatory=$false, HelpMessage="Whether to include the WSI account in the security policy.")]
    [bool]$includeWSIAccount = $true,
    
    [parameter(Mandatory=$false, HelpMessage="The name of the WSI account to include in the security policy.")]
    [ValidateNotNullOrEmpty()]
    [string]$wsiAccountName = "wsiaccount"
)
begin {
    function Test-UserLoggedOn() {
        Write-Verbose "Checking if any users are currently logged on..."
        try {
            $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
            if ($explorerProcesses) {
                Write-Verbose "Found $($explorerProcesses.Count) explorer process(es) - users are logged on"
                return $true
            } else {
                Write-Verbose "No explorer processes found - no users logged on"
                return $false
            }
        }
        catch {
            Write-Error "Failed to check for logged on users: $_"
            return $false
        }
    }
    
    function Get-LoggedOnUsers() {
        Write-Verbose "Retrieving currently logged on users..."
        try {
            $loggedOnUser = (Get-Process -Name explorer -IncludeUserName | Select-Object UserName -Unique).UserName
            if (-NOT[string]::IsNullOrEmpty($loggedOnUser)) {
                Write-Verbose "Found logged on user(s): $($loggedOnUser -join ', ')"
                Write-Output $loggedOnUser
            }
            else {
                Write-Verbose "No logged on users found"
                $null = $loggedOnUser
            }
        }
        catch { 
            Write-Error "Failed to retrieve the username of the logged on user: $_"
            throw
        }
    }
    function Get-AccountSID() {
        param (
            [string]$commonName
        )
        Write-Verbose "Getting SID for account: $commonName"
        try {
            $account = New-Object System.Security.Principal.NTAccount($commonName)  
            $accountSID = $account.Translate([System.Security.Principal.SecurityIdentifier])
            if (-NOT[string]::IsNullOrEmpty($accountSID)) {
                Write-Verbose "SID for $commonName is: $accountSID"
                Write-Output $accountSID
            }
            else {
                $null = $accountSID
            }
        }
        catch {
            Write-Error "Failed to retrieve the SID of the user: $_"
            throw
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
            Write-Error "Failed to retrieve the current configuration of SeInteractiveLogonRight: $_"
            throw
        }
    }
    function Set-SeInterActiveLogonRightConfig() {
        param (
            [string]$currentConfig,
            [string]$newConfig
        )
        Write-Verbose "Applying new SeInteractiveLogonRight configuration..."
        try {
            (Get-Content $global:tmpFile).Replace($currentConfig,$newConfig) | Set-Content $global:tmpFile
            $null = secedit.exe /configure /db secedit.sdb /cfg $global:tmpFile /areas USER_RIGHTS
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Security policy updated successfully"
                $global:remediationSuccess += $true
            } else {
                throw "secedit.exe failed with exit code: $LASTEXITCODE"
            }
        }
        catch {
            Write-Error "Failed to set the new configuration of SeInteractiveLogonRight: $_"
            throw
        }
        finally {
            # Ensure cleanup happens even if there's an error
            if (Test-Path $global:tmpFile) {
                Remove-Item -Path $global:tmpFile -Force -ErrorAction SilentlyContinue
                Write-Verbose "Temporary file cleaned up: $global:tmpFile"
            }
        }
    }
    if ($runDetection -eq $false) {
        Write-Error "runDetection cannot be set to false. As a minimum runDetection must be set to true."
        exit 1
    }
    
    # Early check to ensure users are logged on before proceeding
    if (-not (Test-UserLoggedOn)) {
        Write-Output "[INFO] No users are currently logged on to the computer. Script will exit without making changes."
        exit 0
    }
}
process {
    $global:tmpFile = "$env:windir\Temp\secedit.tmp"
    $global:needsRemediation = @()
    $global:remediationSuccess = @()
    $loggedonUserSID = @()
    $loggedOnUsers = Get-LoggedOnUsers
    $trustedGroupSID = Get-AccountSID -commonName $trustedGroup
    
    # Get WSI account name if enabled (use computername\username format)
    $wsiAccountFullName = $null
    if ($includeWSIAccount) {
        $computerName = $env:COMPUTERNAME
        $wsiAccountFullName = "$computerName\WsiAccount"
        Write-Verbose "WSI account will be added as: $wsiAccountFullName"
    }
    if (-NOT[string]::IsNullOrEmpty($loggedOnUsers)) {
        if ($runDetection -eq $true) {
            $currentConfig = Get-SeInterActiveLogonRightConfig
            $trimCurrentConfig = $currentConfig -split "," | ForEach-Object { $_ -replace "SeInteractiveLogonRight = " }
            foreach ($loggedOnUser in $loggedOnUsers) {
                $loggedonUserSID += Get-AccountSID -commonName $loggedOnUser
            }
            foreach ($userSID in $loggedonUserSID) {
                $sidWithPrefix = "*$($userSID)"
                if ($trimCurrentConfig -notcontains $sidWithPrefix) {
                    Write-Output "[WARNING] the user's SID: $userSID is NOT added to the security policy: SeInteractiveLogonRight"  
                    $global:needsRemediation += $true
                }
                elseif ($trimCurrentConfig -contains $sidWithPrefix) {
                    Write-Output "[OK] the user's SID: $userSID is already added to the security policy: SeInteractiveLogonRight"
                    $global:needsRemediation += $false
                }
            }
        }
        if ($runRemediation -eq $true) {
            if ($global:needsRemediation -contains $true) {
                # Build new configuration starting with built-in Administrators
                $newConfig = "SeInteractiveLogonRight = *S-1-5-32-544"
                
                # Add trusted group if available
                if ($trustedGroupSID) {
                    $newConfig += ",*$($trustedGroupSID.Value)"
                }
                
                # Add WSI account if enabled (by name, not SID)
                if ($includeWSIAccount -and $wsiAccountFullName) {
                    $newConfig += ",$wsiAccountFullName"
                    Write-Verbose "Added WSI account to security policy: $wsiAccountFullName"
                }
                
                # Add all logged on user SIDs
                foreach ($sid in $loggedonUserSID) {
                    $newConfig += ",*$($sid.Value)"
                }
                
                Write-Verbose "New security policy configuration: $newConfig"
                Set-SeInterActiveLogonRightConfig -currentConfig $currentConfig -newConfig $newConfig
            }
        }
    }
}
end {
    # Ensure cleanup of temporary files
    if (Test-Path $global:tmpFile) {
        Remove-Item -Path $global:tmpFile -Force -ErrorAction SilentlyContinue
        Write-Verbose "Final cleanup of temporary file: $global:tmpFile"
    }
    
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
