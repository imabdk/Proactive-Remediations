# Clear-WindowsUpdatePolicies.ps1
# Purpose: Delete all subkeys and values under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate,
# rename Registry.pol, run gpupdate /force, and restart wuauserv for co-managed devices where Intune
# manages the Windows Update workload. No logging included.

try {
    # Define registry path
    $UpdateKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    # Delete all values and subkeys under WindowsUpdate
    if (Test-Path $UpdateKey) {
        # Delete values directly under WindowsUpdate
        $Values = Get-ItemProperty -Path $UpdateKey -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*
        if ($Values.PSObject.Properties.Count -gt 0) {
            foreach ($Value in $Values.PSObject.Properties) {
                Remove-ItemProperty -Path $UpdateKey -Name $Value.Name -Force -ErrorAction SilentlyContinue
            }
        }

        # Delete all subkeys (e.g., AU, Defer)
        $SubKeys = Get-ChildItem -Path $UpdateKey -ErrorAction SilentlyContinue
        foreach ($SubKey in $SubKeys) {
            Remove-Item -Path $SubKey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Rename Registry.pol to clear cached GPO policies
    $RegistryPol = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
    if (Test-Path $RegistryPol) {
        Rename-Item -Path $RegistryPol -NewName "Registry.old" -Force -ErrorAction SilentlyContinue
    }

    # Run gpupdate /force to refresh Group Policy
    #Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow -ErrorAction SilentlyContinue

    # Restart Windows Update service
    if (Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    }

    Write-Output "Compliant"
    exit 0
}
catch {
    Write-Output "NonCompliant"
    exit 1
}
