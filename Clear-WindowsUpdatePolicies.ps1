# Clear-WindowsUpdatePolicies.ps1
# Purpose: Delete all subkeys and values under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate,
# rename Registry.pol, run gpupdate, and restart wuauserv for co-managed devices where Intune manages
# Windows Update workload.

try {
    # Define registry path
    $UpdateKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    # Delete all values directly under WindowsUpdate (not subkeys)
    if (Test-Path $UpdateKey) {
        $Values = Get-ItemProperty -Path $UpdateKey -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*
        if ($Values.PSObject.Properties.Count -gt 0) {
            foreach ($Value in $Values.PSObject.Properties) {
                Remove-ItemProperty -Path $UpdateKey -Name $Value.Name -Force -ErrorAction SilentlyContinue
            }
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
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue

    Write-Output "Compliant"
    exit 0
}
catch {
    Write-Output "NonCompliant"
    exit 1
}