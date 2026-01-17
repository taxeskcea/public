# ==============================================================================
# KCEA AVD MASTER CUSTOMIZATION SCRIPT (WIN 11 ENTERPRISE)
# ==============================================================================

# --- 1. SETUP LOGGING ---
$iconFolder = "C:\ProgramData\KCEA\Icons"
$LogFile = "$iconFolder\cleanup_log.txt"
if (!(Test-Path $iconFolder)) { New-Item -Path $iconFolder -ItemType Directory -Force | Out-Null }

function Log {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $message = "$timestamp - $($args -join ' ')"
    Write-Host $message
    Add-Content -Path $LogFile -Value $message
}

Log "----------------------------------------------------------------"
Log "Starting Master Cleanup Script for Win 11 Enterprise"

# --- 2. ELEVATION CHECK ---
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Log "CRITICAL: Script not running as Admin. Elevation required."
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# --- 3. BLOATWARE REMOVAL (Merged Win10 & Win11 Lists) ---
$packagesToRemove = @(
    "Microsoft.Teams", "Microsoft.MicrosoftStickyNotes", "Microsoft.Copilot",
    "Microsoft.Getstarted", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote", "Microsoft.People", "Microsoft.SkypeApp",
    "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "*Xbox*",
    "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo",
    "Microsoft.WebMediaExtensions", "Clipchamp.Clipchamp", "Microsoft.BingNews",
    "Microsoft.BingWeather", "Microsoft.OutlookForWindows", "Microsoft.BingSearch",
    "*GamingApp*", "*Xbox*", "*Solitaire*", "*BingNews*", "*BingWeather*", 
    "*YourPhone*", "*Clipchamp*", "*FeedbackHub*", "*GetHelp*", 
    "*ZuneMusic*", "*OfficeHub*", "*OutlookForWindows*", "*Teams*", 
    "*StickyNotes*", "*Gallery*", "*XboxSpeechToTextOverlay*"
)

foreach ($package in $packagesToRemove) {
    Log "Processing AppX: $package"
    try {
        # Provisioned (New Users)
        $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $package -or $_.PackageName -like $package }
        if ($prov) {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop
            Log "  [SUCCESS] Provisioned $package removed."
        }
        # Installed (Current Users)
        $inst = Get-AppxPackage -Name $package -AllUsers
        if ($inst) {
            Remove-AppxPackage -Package $inst.PackageFullName -AllUsers -ErrorAction Stop
            Log "  [SUCCESS] Installed $package removed."
        }
    } catch { Log "  [ERROR] Failed to remove $package - $_" }
}

# --- 4. DISABLE WINDOWS FEATURES ---
Log "Processing Windows Optional Features..."
$features = @("WindowsMediaPlayer", "WorkFolders-Client")
foreach ($feature in $features) {
    try {
        Log "  Attempting to disable: $feature"
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
        Log "  [SUCCESS] $feature disabled."
    } catch { Log "  [ERROR] Failed to disable $feature - $_" }
}

# --- 5. REGISTRY HARDENING (Copilot & Explorer Cleanup) ---
Log "Applying Registry Tweaks..."
$regSettings = @(
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1),
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCopilotButton", 0)
)
foreach ($set in $regSettings) {
    if (!(Test-Path $set[0])) { New-Item -Path $set[0] -Force | Out-Null }
    Set-ItemProperty -Path $set[0] -Name $set[1] -Value $set[2] -Type DWORD
}

# Hide Gallery, Music, Pictures, Videos from sidebar
$FolderGUIDs = @(
    "{e88865ad-11a6-40f3-969d-762f0e0c9c41}", # Gallery
    "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}", # Music
    "{24ad3ad2-a996-4a41-a3aa-4e3283a3c186}", # Pictures
    "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"  # Videos
)
foreach ($guid in $FolderGUIDs) {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\$guid\PropertyBag"
    if (Test-Path $path) { Set-ItemProperty -Path $path -Name "ThisPCPolicy" -Value "Hide" }
}

# --- 6. DRIVE SHORTCUTS WITH ICONS ---
Log "Downloading Icons and Creating Desktop Shortcuts..."
$kIconUrl = "https://raw.githubusercontent.com/taxeskcea/public/main/K.ico"
$zIconUrl = "https://raw.githubusercontent.com/taxeskcea/public/main/Z.ico"

try {
    Invoke-WebRequest -Uri $kIconUrl -OutFile "$iconFolder\K.ico" -ErrorAction Stop
    Invoke-WebRequest -Uri $zIconUrl -OutFile "$iconFolder\Z.ico" -ErrorAction Stop
    Log "  [SUCCESS] Icons downloaded to $iconFolder"
} catch { Log "  [ERROR] Failed to download icons - $_" }

$shell = New-Object -ComObject WScript.Shell
$driveConfig = @(
    @{ Name = "K Drive"; Target = "K:"; Icon = "$iconFolder\K.ico" },
    @{ Name = "Z Drive"; Target = "Z:"; Icon = "$iconFolder\Z.ico" }
)

foreach ($item in $driveConfig) {
    $lnk = $shell.CreateShortcut("C:\Users\Public\Desktop\$($item.Name).lnk")
    $lnk.TargetPath = "explorer.exe"
    $lnk.Arguments = $item.Target
    $lnk.IconLocation = "$($item.Icon), 0" 
    $lnk.Save()
    Log "  [SUCCESS] Created shortcut for $($item.Name)"
}

Log "Cleanup Complete. Restarting Explorer to finalize UI changes."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue