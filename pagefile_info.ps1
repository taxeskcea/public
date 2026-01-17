$auto = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
$usage = Get-CimInstance Win32_PageFileUsage

Write-Host "--- Pagefile Report ---" -ForegroundColor Cyan
Write-Host "Auto-Managed: $auto"
foreach ($file in $usage) {
    Write-Host "Location:     $($file.Name)"
    Write-Host "Current Size: $($file.AllocatedBaseSize) MB"
    Write-Host "Current Use:  $($file.CurrentUsage) MB"
    Write-Host "Peak Use:     $($file.PeakUsage) MB"
    Write-Host "-----------------------"
}