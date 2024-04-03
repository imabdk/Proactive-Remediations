<#
.SYNOPSIS
    This script checks the state of NetBIOS over TCP/IP on the active network adapter.

.DESCRIPTION
    The script defines two functions, Get-ActiveNetworkCard and Get-NetBiosState. 
    Get-ActiveNetworkCard retrieves the description of the active network interface card (NIC).
    Get-NetBiosState retrieves the current NetBIOS over TCP/IP setting for the active NIC.
    The script then checks if NetBIOS is disabled. If it is not, it outputs a warning message and exits with a status of 1. 
    If NetBIOS is disabled, it outputs a confirmation message and exits with a status of 0.

.NOTES
    Filename: Detect-NetBiosState.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.EXAMPLE
    .\Detect-NetBiosState.ps1

    Checks the state of NetBIOS over TCP/IP on the active network adapter and outputs a message indicating whether it is disabled or not.

.LINKS
    https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration
#>

begin {
    function Get-ActiveNetworkCard() {
        try {
            $activeNIC = (Get-NetAdapter | Where-Object {$_.Status -eq "Up" -AND $_.ConnectorPresent -eq $True} | Select-Object InterfaceDescription).InterfaceDescription
        } catch { 
            $activeNIC = $null    
        }
        if (-NOT[string]::IsNullOrEmpty($activeNIC)) {
            Write-Output $activeNIC
        }
    }
    function Get-NetBiosState() {
        try {
            $netBiosOptionStatus = ((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter "Description = '$(Get-ActiveNetworkCard)'" | Select-Object -Property @('Description', 'TcpipNetbiosOptions'))).TcpipNetbiosOptions
        } catch {
            $netBiosOptionStatus = $null
        }
        switch ($netBiosOptionStatus) {
            0 {$netBiosOptionDesc = "EnableNetbiosViaDhcp"}
            1 {$netBiosOptionDesc = "EnableNetbios"}
            2 {$netBiosOptionDesc = "DisableNetbios"}
        }    
        if (-NOT[string]::IsNullOrEmpty($netBiosOptionStatus)) {
            Write-Output $netBiosOptionStatus
            Write-Output $netBiosOptionDesc
        }
    }
}
process {
    if ((Get-NetBiosState)[0] -ne 2) {
        Write-Output "[Warning] NetBios is NOT disabled, and is currently configured to: $(Get-NetBiosState)"
        exit 1
    }
    elseif ((Get-NetBiosState)[0] -eq 2) {
        Write-Output "[OK] NetBios is already disabled, and is currently configured to: $(Get-NetBiosState)"
        exit 0
    }
}
end {
    #Nothing to see here
}  
