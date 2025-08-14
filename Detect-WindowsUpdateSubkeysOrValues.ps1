# Detect-WindowsUpdateSubkeysOrValues.ps1
# Purpose: Detect any subkeys or values under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
# for co-managed devices where Intune manages Windows Update workload.

try {
    # Define registry path
    $UpdateKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    # Check for subkeys or values under WindowsUpdate
    if (Test-Path $UpdateKey) {
        # Check for subkeys
        $SubKeys = Get-ChildItem -Path $UpdateKey -ErrorAction SilentlyContinue
        # Check for values directly under the key
        $Values = Get-ItemProperty -Path $UpdateKey -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*

        if ($SubKeys -and $SubKeys.Count -gt 0 -or $Values.PSObject.Properties.Count -gt 0) {
            Write-Output "NonCompliant"
            exit 1
        }
    }

    # If no subkeys or values, or key doesn't exist, return Compliant
    Write-Output "Compliant"
    exit 0
}
catch {
    Write-Output "NonCompliant"
    exit 1
}