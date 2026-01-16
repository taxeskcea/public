# --- Bloatware Removal List (Provisioned Packages) ---
$bloatware = @(
    "Microsoft.Teams",
    "Microsoft.MicrosoftStickyNotes"
    "*GamingApp*",            # Xbox App
    "*Xbox*",                 # All other Xbox components
    "*SolitaireCollection*",  # Solitaire
    "*BingNews*",             # Microsoft News
    "*BingWeather*",          # MSN Weather
    "*YourPhone*",            # Phone Link
    "*Clipchamp*",            # Video Editor
    "*WindowsFeedbackHub*",   # Feedback Hub
    "*GetHelp*",              # Get Help
    "*ZuneMusic*",            # Windows Media Player (Legacy/UWP)
    "*MicrosoftOfficeHub*"    # "Office" app (not the actual apps, just the shortcut hub)
)

Write-Output "De-provisioning consumer bloatware from the system image..."

foreach ($app in $bloatware) {
    # 1. Remove from the current logged-in user
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    
    # 2. Remove from the "Provisioning" list (Prevents re-install for new users)
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } | 
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

Write-Output "Bloatware removal complete."