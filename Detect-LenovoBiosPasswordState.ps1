<#
.DESCRIPTION
    Find and locate Lenovo devices where no supervisor password has been configured.
    Script is intended to be used with Proactive Remediations in Microsoft Intune
    Script will output the current password state

.NOTES
    Filename: Detect-LenovoBiosPasswordState.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINK
    https://www.imab.dk/inventory-lenovo-bios-password-states-using-powershell-and-proactive-remediations
#> 
#region Functions
# Get-ComputerModel function. Used for determining if a Lenovo device or not
function Get-ComputerModel() {
    $computerModel = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).Vendor
    if ($computerModel -ne "LENOVO") {
        Write-Output "NOT LENOVO"
    }
    else {
        Write-Output "LENOVO"
    }
}
# Get-BiosPasswordState function. Used to output the current BIOS config in regards to passwords
function Get-BiosPasswordState() {
    $passwordState = (Get-WmiObject -Namespace root\wmi -Class Lenovo_BiosPasswordSettings).PasswordState
    switch ($passwordState) {
        0 { $returnMessage = 'No passwords set' }
        2 { $returnMessage = 'Supervisor password set' }
        3 { $returnMessage = 'Power on and supervisor passwords set' }
        4 { $returnMessage = 'Hard drive password(s) set' }
        5 { $returnMessage = 'Power on and hard drive passwords set' }
        6 { $returnMessage = 'Supervisor and hard drive passwords set' }
        7 { $returnMessage = 'Supervisor, power on, and hard drive passwords set' }
    }
    Write-Output $passwordState
    Write-Output $returnMessage
}
#endregion

#region Execution
# Accepted password states, translating into that a BIOS password is configured
# If password state is not equal to any of these, this means a BIOS password is not configured
$global:approvedConfigs = "2","3","6","7"
try {
    $isLenovo = Get-ComputerModel
    if ($isLenovo -eq "LENOVO") {
        $status = Get-BIOSPasswordState
        if ($status[0] -notin $global:approvedConfigs) {
            Write-Output "BIOS is not configured with a supervisor password. BIOS config message: $($status[1])"
            exit 1
        }
        elseif ($status[0] -in $global:approvedConfigs) {
            Write-Output "BIOS is configured with a supervisor password. BIOS config message: $($status[1])"
            exit 0
        }
    }
    elseif ($isLenovo -ne "LENOVO") {
        Write-Output "Not a Lenovo device. Doing nothing"
        exit 0        
    }
}
catch { 
    Write-Output "Script failed to run"
}
finally { 
    # Nothing to see here
}
#endregion