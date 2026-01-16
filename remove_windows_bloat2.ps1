# --- 1. Hardened Bloatware Removal (Run as SYSTEM/Admin) ---
$bloatList = @(
    "Microsoft.BingNews", 
    "Microsoft.BingWeather", 
    "Microsoft.GamingApp",      # Xbox
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",      # Phone Link
    "Clipchamp.Clipchamp",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.GetHelp",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.ZuneMusic",      # Legacy Media Player
    "Microsoft.BingSearch"      # Bing Search / News
)

Write-Output "Starting deep-clean of AppX Provisioned Packages..."

foreach ($app in $bloatList) {
    # Remove from the "Provisioning" list so NEW users never see them
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq $app} | 
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    
    # Remove for ALL current users (handles the 'Access Denied' better)
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    
    Write-Output "Successfully processed $app"
}

# --- 2. Disable Consumer Features (Registry) ---
# This prevents Windows from auto-installing "Suggested" apps (TikTok, Disney+)
Write-Output "Disabling Windows 11 Consumer Features..."
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force }
Set-ItemProperty -Path $RegPath -Name "DisableWindowsConsumerFeatures" -Value 1