<#
.SYNOPSIS
    Detects if the current user is added to the security policy: SeInteractiveLogonRight. 
    If the user is not added the script will add the user to the Allow logon locally' security policy.  
    The script is designed to be run as a detection and remediation script in Microsoft Intune.   
    
.DESCRIPTION
    This script manages the SeInteractiveLogonRight security policy to ensure currently logged-on users
    have permission to log on locally. It can run in detection-only mode or perform automatic remediation.
    
    Version 3.0 adds comprehensive account validation and dynamic MEM service account support.
    
    The script:
    1. Identifies currently logged-on users
    2. Checks if they have SeInteractiveLogonRight permission
    3. Validates that trusted groups and service accounts are also configured
    4. Dynamically includes MEM service accounts based on logged-on users
    5. Optionally adds missing users and accounts to the security policy
    6. Maintains existing permissions for built-in groups
    7. Validates configurations before applying changes
    8. Includes retry logic for failed operations

.PARAMETER runDetection
    Whether to run the detection phase. Cannot be set to false as detection is required.
    Default: $true

.PARAMETER runRemediation  
    Whether to run the remediation phase if issues are detected.
    Default: $false

.PARAMETER trustedGroup
    The trusted group to include in the security policy. 
    Default: "DOMAIN\TRUSTED GROUP"

.PARAMETER includeWSIAccount
    Whether to include the WSI account in the security policy.
    The account will be added using its SID for better compatibility.
    Default: $true

.PARAMETER wsiAccountName
    The name of the WSI account to include in the security policy.
    Default: "wsiaccount"

.PARAMETER includeMEMAccount
    Whether to include MEM service accounts based on logged-on users.
    The account will be dynamically constructed as MEM\KM_<USERNAME>_$
    Default: $true

.EXAMPLE
    .\Detect-Remediate-LockToUser.ps1
    Runs detection only with default settings (remediation disabled by default).

.EXAMPLE
    .\Detect-Remediate-LockToUser.ps1 -runRemediation $true
    Runs both detection and remediation with default settings.

.EXAMPLE
    .\Detect-Remediate-LockToUser.ps1 -Verbose
    Runs with verbose output for troubleshooting.

.EXAMPLE
    .\Detect-Remediate-LockToUser.ps1 -includeMEMAccount $false -runRemediation $true
    Runs detection and remediation but excludes MEM service accounts.

.NOTES
    Filename: Detect-Remediate-LockToUser.ps1
    Version: 3.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson
    Modified by: MAB (Kromann Reumert)
    
    Version History:
    3.0 - Added comprehensive detection for all required accounts (not just users)
        - Added dynamic MEM service account support (MEM\KM_<USERNAME>_$)
        - Detection now validates: logged-on users, trusted group, WSI account, and MEM accounts
        - All missing accounts are flagged during detection phase
        - Remediation adds all required accounts in a single operation
        - Enhanced parameter documentation
        - Added new parameter: includeMEMAccount
    2.0 - Enhanced error handling for secedit operations
        - Added retry logic for failed secedit operations
        - Improved WSI account handling using SID format
        - Added configuration validation before applying changes
        - Better error diagnostics with specific guidance for common issues
        - Robust temporary file management
    1.1 - Previous version
    
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
    [string]$trustedGroup = "DOMAIN\Trusted Group",
    
    [parameter(Mandatory=$false, HelpMessage="Whether to include the WSI account in the security policy.")]
    [bool]$includeWSIAccount = $true,
    
    [parameter(Mandatory=$false, HelpMessage="The name of the WSI account to include in the security policy.")]
    [ValidateNotNullOrEmpty()]
    [string]$wsiAccountName = "wsiaccount",
    
    [parameter(Mandatory=$false, HelpMessage="Whether to include the MEM service account based on logged-on user.")]
    [bool]$includeMEMAccount = $true
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
    function Test-SeInteractiveLogonRightConfig() {
        param (
            [string]$configLine
        )
        Write-Verbose "Validating SeInteractiveLogonRight configuration: $configLine"
        
        if ([string]::IsNullOrEmpty($configLine)) {
            Write-Error "Configuration line is empty"
            return $false
        }
        
        if (-not $configLine.StartsWith("SeInteractiveLogonRight = ")) {
            Write-Error "Configuration line does not start with 'SeInteractiveLogonRight = '"
            return $false
        }
        
        # Extract the accounts part
        $accountsPart = $configLine.Substring("SeInteractiveLogonRight = ".Length)
        if ([string]::IsNullOrEmpty($accountsPart)) {
            Write-Error "No accounts specified in configuration"
            return $false
        }
        
        # Split and validate each account
        $accounts = $accountsPart -split ","
        foreach ($account in $accounts) {
            $trimmedAccount = $account.Trim()
            if ([string]::IsNullOrEmpty($trimmedAccount)) {
                Write-Error "Empty account found in configuration"
                return $false
            }
            
            # Check if it's a SID (starts with *S-) or account name
            if ($trimmedAccount.StartsWith("*S-")) {
                # Validate SID format (basic check)
                if ($trimmedAccount -notmatch "^\*S-\d+-\d+(-\d+)*$") {
                    Write-Error "Invalid SID format: $trimmedAccount"
                    return $false
                }
            } elseif (-not $trimmedAccount.Contains("\")) {
                # Account names should contain domain\username format for most cases
                Write-Warning "Account '$trimmedAccount' may not be in proper domain\username format"
            }
        }
        
        Write-Verbose "Configuration validation passed"
        return $true
    }
    
    function Get-SeInterActiveLogonRightConfig() {
        try {
            Write-Verbose "Exporting security configuration to temporary file..."
            $exportResult = secedit.exe /export /cfg $global:tmpFile 2>&1
            
            if ($LASTEXITCODE -ne 0) {
                Write-Error "secedit.exe export failed with exit code: $LASTEXITCODE. Output: $exportResult"
                throw "Failed to export security configuration"
            }
            
            if (-not (Test-Path $global:tmpFile)) {
                Write-Error "Temporary file was not created: $global:tmpFile"
                throw "Security configuration export did not create expected file"
            }
            
            $fileContent = Get-Content $global:tmpFile -ErrorAction Stop
            if (-not $fileContent) {
                Write-Error "Temporary file is empty or unreadable: $global:tmpFile"
                throw "Security configuration file is empty"
            }
            
            $currentConfig = $fileContent | Where-Object { $_ -like "SeInterActiveLogonRight*" }
            if (-NOT[string]::IsNullOrEmpty($currentConfig)) {
                Write-Verbose "Current SeInteractiveLogonRight configuration: $currentConfig"
                Write-Output $currentConfig
            }
            else {
                Write-Warning "SeInteractiveLogonRight not found in security configuration"
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
            # Validate inputs
            if ([string]::IsNullOrEmpty($currentConfig)) {
                throw "Current configuration is empty or null"
            }
            if ([string]::IsNullOrEmpty($newConfig)) {
                throw "New configuration is empty or null"
            }
            
            # Validate temporary file exists and is readable
            if (-not (Test-Path $global:tmpFile)) {
                throw "Temporary file does not exist: $global:tmpFile"
            }
            
            # Validate the new configuration before applying
            if (-not (Test-SeInteractiveLogonRightConfig -configLine $newConfig)) {
                throw "New configuration failed validation: $newConfig"
            }
            
            # Update the configuration file
            Write-Verbose "Updating configuration file with new policy..."
            $content = Get-Content $global:tmpFile -ErrorAction Stop
            $updatedContent = $content -replace [regex]::Escape($currentConfig), $newConfig
            $updatedContent | Set-Content $global:tmpFile -ErrorAction Stop
            
            # Verify the replacement was successful
            $verifyContent = Get-Content $global:tmpFile -ErrorAction Stop
            if ($verifyContent -notcontains $newConfig) {
                throw "Failed to update configuration file - new configuration not found"
            }
            
            Write-Verbose "New configuration written to file: $newConfig"
            
            # Apply the configuration with retry logic
            $maxRetries = 3
            $retryCount = 0
            $success = $false
            
            while ($retryCount -lt $maxRetries -and -not $success) {
                $retryCount++
                Write-Verbose "Applying security configuration (attempt $retryCount of $maxRetries)..."
                
                # Create a new database file for each attempt to avoid corruption
                $dbFile = "$env:windir\Temp\secedit_$retryCount.sdb"
                
                try {
                    $configureResult = secedit.exe /configure /db $dbFile /cfg $global:tmpFile /areas USER_RIGHTS /quiet 2>&1
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Security policy updated successfully on attempt $retryCount"
                        $global:remediationSuccess += $true
                        $success = $true
                    } else {
                        $errorMessage = "secedit.exe configure failed with exit code: $LASTEXITCODE"
                        if ($configureResult) {
                            $errorMessage += ". Output: $configureResult"
                        }
                        
                        # Provide specific guidance for common exit codes
                        switch ($LASTEXITCODE) {
                            1 { $errorMessage += ". This usually indicates a syntax error in the configuration file or invalid account names." }
                            2 { $errorMessage += ". This usually indicates the specified file could not be found." }
                            3 { $errorMessage += ". This usually indicates insufficient privileges to modify security policy." }
                            default { $errorMessage += ". Unknown error code." }
                        }
                        
                        if ($retryCount -eq $maxRetries) {
                            throw $errorMessage
                        } else {
                            Write-Warning "$errorMessage Retrying in 2 seconds..."
                            Start-Sleep -Seconds 2
                        }
                    }
                } finally {
                    # Clean up database file
                    if (Test-Path $dbFile) {
                        Remove-Item -Path $dbFile -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            if (-not $success) {
                throw "Failed to apply security configuration after $maxRetries attempts"
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
    
    # Get WSI account SID if enabled
    $wsiAccountSID = $null
    if ($includeWSIAccount) {
        $computerName = $env:COMPUTERNAME
        $wsiAccountFullName = "$computerName\$wsiAccountName"
        Write-Verbose "Attempting to get SID for WSI account: $wsiAccountFullName"
        try {
            $wsiAccountSID = Get-AccountSID -commonName $wsiAccountFullName
            Write-Verbose "WSI account SID: $wsiAccountSID"
        } catch {
            Write-Warning "Failed to get SID for WSI account '$wsiAccountFullName': $_. WSI account will be skipped."
            $wsiAccountSID = $null
        }
    }
    
    # Get MEM service account SIDs if enabled (one per logged-on user)
    $memAccountSIDs = @()
    if ($includeMEMAccount -and -NOT[string]::IsNullOrEmpty($loggedOnUsers)) {
        foreach ($loggedOnUser in $loggedOnUsers) {
            # Extract username from domain\username format
            if ($loggedOnUser -match '\\(.+)$') {
                $username = $matches[1].ToUpper()
                $memAccountFullName = "MEM\KM_$($username)_`$"
                Write-Verbose "Attempting to get SID for MEM service account: $memAccountFullName"
                try {
                    $memAccountSID = Get-AccountSID -commonName $memAccountFullName
                    $memAccountSIDs += $memAccountSID
                    Write-Verbose "MEM service account SID: $memAccountSID"
                } catch {
                    Write-Warning "Failed to get SID for MEM account '$memAccountFullName': $_. MEM account will be skipped for user $loggedOnUser."
                }
            }
        }
    }
    if (-NOT[string]::IsNullOrEmpty($loggedOnUsers)) {
        if ($runDetection -eq $true) {
            $currentConfig = Get-SeInterActiveLogonRightConfig
            $trimCurrentConfig = $currentConfig -split "," | ForEach-Object { ($_ -replace "SeInteractiveLogonRight = ", "").Trim() }
            
            Write-Verbose "Raw current configuration: $currentConfig"
            Write-Verbose "Current configured SIDs (count: $($trimCurrentConfig.Count)): $($trimCurrentConfig -join ' | ')"
            Write-Verbose "Each configured SID:"
            foreach ($sid in $trimCurrentConfig) {
                Write-Verbose "  - '$sid' (Length: $($sid.Length))"
            }
            
            foreach ($loggedOnUser in $loggedOnUsers) {
                $loggedonUserSID += Get-AccountSID -commonName $loggedOnUser
            }
            
            # Check logged-on users
            foreach ($userSID in $loggedonUserSID) {
                $sidWithPrefix = "*$($userSID)"
                Write-Verbose "Checking if '$sidWithPrefix' is in configuration"
                if ($trimCurrentConfig -notcontains $sidWithPrefix) {
                    Write-Output "[WARNING] the user's SID: $userSID is NOT added to the security policy: SeInteractiveLogonRight"  
                    $global:needsRemediation += $true
                }
                elseif ($trimCurrentConfig -contains $sidWithPrefix) {
                    Write-Output "[OK] the user's SID: $userSID is already added to the security policy: SeInteractiveLogonRight"
                    $global:needsRemediation += $false
                }
            }
            
            # Check trusted group
            if ($trustedGroupSID) {
                $sidWithPrefix = "*$($trustedGroupSID.Value)"
                Write-Verbose "Checking if trusted group '$sidWithPrefix' is in configuration"
                if ($trimCurrentConfig -notcontains $sidWithPrefix) {
                    Write-Output "[WARNING] Trusted group SID: $($trustedGroupSID.Value) ($trustedGroup) is NOT added to the security policy: SeInteractiveLogonRight"
                    $global:needsRemediation += $true
                }
                else {
                    Write-Output "[OK] Trusted group SID: $($trustedGroupSID.Value) ($trustedGroup) is already added to the security policy: SeInteractiveLogonRight"
                    $global:needsRemediation += $false
                }
            }
            
            # Check WSI account
            if ($includeWSIAccount -and $wsiAccountSID) {
                $sidWithPrefix = "*$($wsiAccountSID.Value)"
                $accountNameAlternative = $wsiAccountName
                
                Write-Verbose "Checking if WSI account '$sidWithPrefix' or account name '$accountNameAlternative' is in configuration"
                
                # Check if either the SID format or the account name is present
                if (($trimCurrentConfig -notcontains $sidWithPrefix) -and ($trimCurrentConfig -notcontains $accountNameAlternative)) {
                    Write-Output "[WARNING] WSI account SID: $($wsiAccountSID.Value) is NOT added to the security policy: SeInteractiveLogonRight"
                    $global:needsRemediation += $true
                }
                else {
                    if ($trimCurrentConfig -contains $sidWithPrefix) {
                        Write-Output "[OK] WSI account SID: $($wsiAccountSID.Value) is already added to the security policy: SeInteractiveLogonRight (as SID)"
                    } else {
                        Write-Output "[OK] WSI account is already added to the security policy: SeInteractiveLogonRight (as account name: $accountNameAlternative)"
                    }
                    $global:needsRemediation += $false
                }
            }
            
            # Check MEM service accounts
            if ($includeMEMAccount -and $memAccountSIDs.Count -gt 0) {
                foreach ($memSID in $memAccountSIDs) {
                    $sidWithPrefix = "*$($memSID.Value)"
                    Write-Verbose "Checking if MEM account '$sidWithPrefix' is in configuration"
                    if ($trimCurrentConfig -notcontains $sidWithPrefix) {
                        Write-Output "[WARNING] MEM service account SID: $($memSID.Value) is NOT added to the security policy: SeInteractiveLogonRight"
                        $global:needsRemediation += $true
                    }
                    else {
                        Write-Output "[OK] MEM service account SID: $($memSID.Value) is already added to the security policy: SeInteractiveLogonRight"
                        $global:needsRemediation += $false
                    }
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
                
                # Add WSI account if enabled and SID was retrieved successfully
                if ($includeWSIAccount -and $wsiAccountSID) {
                    $newConfig += ",*$($wsiAccountSID.Value)"
                    Write-Verbose "Added WSI account to security policy with SID: $($wsiAccountSID.Value)"
                }
                
                # Add MEM service accounts if enabled and SIDs were retrieved successfully
                if ($includeMEMAccount -and $memAccountSIDs.Count -gt 0) {
                    foreach ($memSID in $memAccountSIDs) {
                        $newConfig += ",*$($memSID.Value)"
                        Write-Verbose "Added MEM service account to security policy with SID: $($memSID.Value)"
                    }
                }
                
                # Add all logged on user SIDs
                foreach ($sid in $loggedonUserSID) {
                    $newConfig += ",*$($sid.Value)"
                }
                
                Write-Verbose "New security policy configuration: $newConfig"
                
                # Validate the new configuration before applying
                if (-not (Test-SeInteractiveLogonRightConfig -configLine $newConfig)) {
                    Write-Error "Generated configuration failed validation. Configuration: $newConfig"
                    $global:needsRemediation += $false
                } else {
                    Set-SeInterActiveLogonRightConfig -currentConfig $currentConfig -newConfig $newConfig
                }
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
