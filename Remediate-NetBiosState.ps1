<#
.SYNOPSIS
    This script checks the state of NetBIOS over TCP/IP on the active network adapter and attempts to disable it if it's not already.

.DESCRIPTION
    The script defines two functions, Get-ActiveNetworkCard and Get-NetBiosState. 
    Get-ActiveNetworkCard retrieves the description of the active network interface card (NIC).
    Get-NetBiosState retrieves the current NetBIOS over TCP/IP setting for the active NIC.
    The script then checks if NetBIOS is disabled. If it is not, it attempts to disable it and outputs a success message if successful, or an error message if not.

.NOTES
    Filename: Remediate-NetBiosState.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.EXAMPLE
    .\Remediate-NetBiosState.ps1

    Checks the state of NetBIOS over TCP/IP on the active network adapter and attempts to disable it if it's not already.
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
        try {
            Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter "Description = '$activeNetwork'" | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
            Write-Output "[Success] NetBios is now disabled, and is currently configured to: $(Get-NetBiosState)"
            exit 0
        } catch {
            Write-Output "[Error] NetBios was NOT disabled, and is currently configured to: $(Get-NetBiosState)"
            exit 1
        }
    }
}
end {
    #Nothing to see here
}  
