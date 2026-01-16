# ==============================================================================
# AVD APP INSTALLATION SCRIPT
# Includes: PowerShell 7, Adobe, Keeper, GitHub Desktop
# ==============================================================================

# --- Disable UAC Prompts (Auto-Approve) ---
$registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $registryPath -Name "ConsentPromptBehaviorAdmin" -Value 0

# --- Install Apps ---
Write-Output "Starting Headless App Installation..."

# --- 1. PREPARE WINGET ---
# Clear source prompts and force an update to the package index
winget source update --force
Start-Sleep -Seconds 5

# --- 2. INSTALL APPS ---
# We use 'Adobe.Acrobat.Reader.64-bit' as a workaround for the Pro hash error.
# It installs the same unified 64-bit app.
$wingetApps = @(
    "Microsoft.PowerShell",    # PowerShell 7
    "Adobe.Acrobat.Reader.64-bit", 
    "9N040SRQ0S8C",           # Keeper Password Manager
    "GitHub.GitHubDesktop",     # GitHub Desktop
    "Dropbox.Dropbox.MSI"   # Enterprise version - important for FSLogix profiles
)

foreach ($app in $wingetApps) {
    Write-Output "Installing: $app"
    # --force and --scope machine are critical for AVD multi-session
    winget install --id $app --silent --accept-package-agreements --accept-source-agreements --scope machine --force
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Installation of $app failed with code $LASTEXITCODE. Continuing..."
    }
}

# --- 3. K: DRIVE INSTALLERS (PROSERIES / TICTIE) ---
# Note: Use UNC paths as SYSTEM account doesn't see the K: drive.
$InstallerPath = "\\kceafiles.file.core.windows.net\kcea\installers"

# Example for TicTie Calculate (assuming MSI)
# Write-Output "Installing TicTie..."
# Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath\TicTie_Setup.msi`" /qn /norestart" -Wait

Write-Output "App Installation Block Finished."
# --- Re-enable UAC Prompts (Security Best Practice) ---
Set-ItemProperty -Path $registryPath -Name "ConsentPromptBehaviorAdmin" -Value 5
