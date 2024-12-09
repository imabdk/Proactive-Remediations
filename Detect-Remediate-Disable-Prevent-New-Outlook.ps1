<#
.SYNOPSIS
    This script disables and prevents the migration to the new Outlook for logged-on users by modifying specific registry keys.

.DESCRIPTION
    The script performs the following actions:
    1. Detects the logged-on users and retrieves their SIDs.
    2. Checks the registry keys for each logged-on user to ensure they match the expected values.
    3. If discrepancies are found, the script can optionally remediate the registry keys to enforce the expected values.

.PARAMETER runDetection
    Indicates whether the script should run the detection phase. Default is $true.

.PARAMETER runRemediation
    Indicates whether the script should run the remediation phase if discrepancies are found. Default is $true.

.FUNCTIONS
    - Test-RegistryKeyValue: Checks if a registry key value exists.
    - Get-RegistryKeyValue: Retrieves the value of a registry key.
    - Remove-RegistryKeyValue: Removes a registry key value.
    - Install-RegistryKey: Creates a registry key if it does not exist.
    - Set-RegistryKeyValue: Sets the value of a registry key.
    - Invoke-RegistryComplianceCheck: Checks and optionally remediates a registry key value.
    - Get-LoggedOnUser: Retrieves the username of the logged-on user.
    - Get-AccountSID: Retrieves the SID of a user.

.EXAMPLE
    .\Disable-Prevent-New-Outlook.ps1 -runDetection $true -runRemediation $true
    This command runs the script with both detection and remediation phases enabled.

.NOTES
    - The script requires administrative privileges to modify registry keys.
    - Filename: Detect-Remediate-Disable-Prevent-New-Outlook.ps1
    - Author: Martin Bengtsson
    - Blog: www.imab.dk
    - Twitter: @mwbengtsson
#>
#Requires -RunAsAdministrator
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
    #region Functions to modify registry keys
    function Test-RegistryKeyValue() {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$registryPath,
            [Parameter(Mandatory=$true)]
            [string]$registryName
        )
        if (-NOT(Test-Path -Path $registryPath -PathType Container)) {
            return $false
        }
        $registryProperties = Get-ItemProperty -Path $registryPath 
        if (-NOT($registryProperties)) {
            return $false
        }
        $member = Get-Member -InputObject $registryProperties -Name $registryName
        if (-NOT([string]::IsNullOrEmpty($member))) {
            return $true
        }
        else {
            return $false
        }
    }
    function Get-RegistryKeyValue() {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$registryPath,
            [Parameter(Mandatory=$true)]
            [string]$registryName,
            [Parameter(Mandatory=$false)]
            [string]$registryType
        )
        if (-NOT(Test-RegistryKeyValue -registryPath $registryPath -registryName $registryName)) {
            return $null
        }
        if ($registryType -eq "Binary") {
            $value = [string]::join(' ',((Get-ItemProperty -Path $registryPath -Name $registryName).$registryName|ForEach-Object{'{0:x2}' -f $_}))
            $value = $value.Replace(' ',',')
            return $value
        }
        $registryProperties = Get-ItemProperty -Path $registryPath -Name *
        $value = $registryProperties.$registryName
        return $value
    }
    function Remove-RegistryKeyValue() {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param (
            [Parameter(Mandatory=$true)]
            [string]$registryPath,        
            [Parameter(Mandatory=$true)]
            [string]$registryName
        )
        if (Test-RegistryKeyValue -registryPath $registryPath -registryName $registryName) {
            if ($pscmdlet.ShouldProcess(('Item: {0} Property: {1}' -f $registryPath,$registryName),'Remove Property')) {
                Remove-ItemProperty -Path $registryPath -Name $registryName
            }
        }
    }
    function Install-RegistryKey() {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]
            $registryPath
        )
        if (-NOT(Test-Path -Path $registryPath -PathType Container)) {
            New-Item -Path $registryPath -ItemType RegistryKey -Force | Out-String | Write-Verbose
        }
    }
    function Set-RegistryKeyValue() {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$registryPath,
            [Parameter(Mandatory=$true)]
            [string]$registryName,
            [Parameter(Mandatory=$true,ParameterSetName='String')]
            [AllowEmptyString()]
            [AllowNull()]
            [string]$String,
            [Parameter(ParameterSetName='String')]
            [switch]$Expand,
            [Parameter(Mandatory=$true,ParameterSetName='Binary')]
            [string]$Binary,
            [Parameter(Mandatory=$true,ParameterSetName='DWord')]
            [int]$DWord,
            [Parameter(Mandatory=$true,ParameterSetName='DWordAsUnsignedInt')]
            [uint32]$UDWord,
            [Parameter(Mandatory=$true,ParameterSetName='QWord')]
            [long]$QWord,
            [Parameter(Mandatory=$true,ParameterSetName='QWordAsUnsignedInt')]
            [uint64]$UQWord,
            [Parameter(Mandatory=$true,ParameterSetName='MultiString')]
            [string[]]$Strings,
            [switch]$Force
        )
        $value = $null
        $type = $pscmdlet.ParameterSetName
        switch -Exact ($pscmdlet.ParameterSetName) {
            'String' { 
                $value = $String 
                if ($Expand) {
                    $type = 'ExpandString'
                }
            }
            'Binary' { [byte[]]$value = $Binary.Split(',') | ForEach-Object { "0x$_"} }
            'DWord' { $value = $DWord }
            'QWord' { $value = $QWord }
            'DWordAsUnsignedInt' { 
                $value = $UDWord 
                $type = 'DWord'
            }
            'QWordAsUnsignedInt' { 
                $value = $UQWord 
                $type = 'QWord'
            }
            'MultiString' { $value = $Strings }
        }
        Install-RegistryKey -registryPath $registryPath
        if ($Force) {
            Remove-RegistryKeyValue -registryPath $registryPath -registryName $registryName
        }
        if (Test-RegistryKeyValue -registryPath $registryPath -registryName $registryName) {
            $currentValue = Get-RegistryKeyValue -registryPath $registryPath -registryName $registryName
            if ($currentValue -ne $value) {
                Set-ItemProperty -Path $registryPath -Name $registryName -Value $value
            }
        }
        else {
            $null = New-ItemProperty -Path $registryPath -Name $registryName -Value $value -PropertyType $type
        }
    }
    function Invoke-RegistryComplianceCheck() {
        param (
            [Parameter(Mandatory=$true)]
            [string]$registryPath,
            [Parameter(Mandatory=$true)]
            [string]$registryName,
            [Parameter(Mandatory=$true)]
            [string]$registryExpectedValue,
            [Parameter(Mandatory=$true)]
            [string]$registryExpectedType
            )
        if ($registryExpectedType -eq "Binary") {
            $getValue = Get-RegistryKeyValue -registryPath $registryPath -registryName $registryName -registryType $registryExpectedType
        }
        else {
            $getValue = Get-RegistryKeyValue -registryPath $registryPath -registryName $registryName
        }
        if (($getValue -ne $registryExpectedValue) -or ($null -eq $getValue)) {
            if ($null -eq $getValue) { $getValue = "null. (key does not exist)" }
            if ($runDetection -eq $true) { $global:needsRemediation += $true }
            Write-Output "[WARNING] Value of registry key: $registryPath\$registryName is not as expected. Value is: $getValue. Expected value is: $registryExpectedValue."
            if ($runRemediation -eq $true) {
                Write-Output "[INFO] runRemediation is set to $runRemediation. Remediation for $registryPath\$registryName will run."
                try {
                    switch ($registryExpectedType) {
                        "String" { Set-RegistryKeyValue -registryPath $registryPath -registryName $registryName -String $registryExpectedValue -Force -ErrorAction Stop }
                        "Binary" { Set-RegistryKeyValue -registryPath $registryPath -registryName $registryName -Binary $registryExpectedValue -Force -ErrorAction Stop }
                        "Dword" { Set-RegistryKeyValue -registryPath $registryPath -registryName $registryName -DWord $registryExpectedValue -Force -ErrorAction Stop }
                        "MultiString" { Set-RegistryKeyValue -registryPath $registryPath -registryName $registryName -Strings $registryExpectedValue -Force -ErrorAction Stop }
                        default { throw "Unsupported registry type: $registryExpectedType" }
                    }
                    $getValue = Get-RegistryKeyValue -registryPath $registryPath -registryName $registryName
                    if ($getValue -eq $registryExpectedValue) {
                        Write-Output "[INFO] Remediation was successful. Value of registry key: $registryPath\$registryName is now as expected."
                        $global:remediationSuccess += $true
                    }
                }
                catch {
                    Write-Output "[ERROR] An error occurred while trying to remediate $registryPath\$registryName. Error: $_"
                    $global:remediationSuccess += $false                              
                }
            }
        }
        else {
            $global:needsRemediation += $false
        }
    }
    function Get-LoggedOnUser() {
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
    #endregion
    if ($runDetection -eq $false) {
        Write-Output "[ERROR] runDetection cannot be set to false. As a minimum runDetection must be set to true."
        exit 1
    }
}
process {
    #region Execution
    $global:needsRemediation = @()
    $global:remediationSuccess = @()
    $loggedonUserSID = @()
    $loggedOnUsers = Get-LoggedOnUser
    foreach ($loggedOnUser in $loggedOnUsers) {
        $loggedonUserSID += Get-AccountSID -commonName $loggedOnUser
    }
    foreach ($userSID in $loggedonUserSID) {
        $registryEntries = @(
            @{  
                # Hide the new Outlook toggle
                Path = "Registry::HKEY_USERS\$($userSID)\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\General"
                Name = "HideNewOutlookToggle"
                Value = "1"
                Type = "Dword"
            },
            @{  
                # Prevent migrating to new Outlook
                Path = "Registry::HKEY_USERS\$($userSID)\SOFTWARE\Policies\Microsoft\office\16.0\outlook\preferences"
                Name = "NewOutlookMigrationUserSetting"
                Value = "0"
                Type = "Dword"
            }
        )
        foreach ($registryEntry in $registryEntries) {
            Invoke-RegistryComplianceCheck -registryPath $registryEntry.Path -registryName $registryEntry.Name -registryExpectedValue $registryEntry.Value -registryExpectedType $registryEntry.Type
        }
    }
    #endregion
}
end {
    if ($runDetection -eq $true) {
       if ($global:needsRemediation -contains $true -AND $global:remediationSuccess -notcontains $true) {
           Write-Output "[WARNING] Values of one or more policies in registry are not as expected. Remediation is needed."
           exit 1
       }
       elseif ($global:remediationSuccess -contains $true -AND $global:remediationSuccess -notcontains $false) {
           Write-Output "[OK] Remediation was run successfully. Values of all policies in registry are now as expected"
           exit 0
       }
       else {
           Write-Output "[OK] Values of all policies in registry are as expected. Doing nothing."
           exit 0
       }
   }
}
