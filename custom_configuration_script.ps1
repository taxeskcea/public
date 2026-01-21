# =================================================================================
# AVD Provisioning Script (System + User Context)
# =================================================================================
$LogDir = "C:\ProgramData\KCEA\Logs"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force }
$LogFile = "$LogDir\AVD_Provisioning.log"
Start-Transcript -Path $LogFile -Append

# --- REGION 1: SYSTEM-LEVEL SETUP (Runs as SYSTEM) ---
Write-Host "Configuring System Settings and FSLogix Cloud-Only Fixes..."


# 1.0 Download and install FSLogix (If missing)
if (!(Test-Path "HKLM:\SOFTWARE\FSLogix")) {
    Write-Host "FSLogix not found. Installing..."
    $fsLogixDownloadUrl = "https://aka.ms/fslogix_download"
    $downloadPath = "$env:TEMP\FSLogix.zip"
    $extractPath = "$env:TEMP\FSLogix_Extract"

    Invoke-WebRequest -Uri $fsLogixDownloadUrl -OutFile $downloadPath
    Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
    
    # Run the 64-bit installer silently
    $installer = Get-ChildItem -Path "$extractPath\x64\Release" -Filter "FSLogixAppsSetup.exe" | Select-Object -First 1
    Start-Process -FilePath $installer.FullName -ArgumentList "/quiet", "/norestart" -Wait
    
    Write-Host "FSLogix Installation Complete."
}



# 1.1 FSLogix Cloud-Only Stability Keys
# Force the path creation to ensure it exists before writing keys
$fslogixProfilePath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$fslogixODFCPath = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
$storagePath = "\\kceafiles.file.core.windows.net\avdprofiles" # Added for 2 new statements in Core FSLogix Config below

if (!(Test-Path $fslogixProfilePath)) { 
    New-Item -Path "HKLM:\SOFTWARE\FSLogix" -ErrorAction SilentlyContinue
    New-Item -Path $fslogixProfilePath -Force 
}
# Core FSLogix Configuration

Set-ItemProperty -Path $fslogixProfilePath -Name "VolumeType" -Value "vhdx" -Type String -Force
# Type: REG_SZ
# Default Value: vhd
# Data values and use:
# A value of vhd means that newly created files should be of type VHD. A value of vhdx means that newly created files should be of type VHDX.


Set-ItemProperty -Path $fslogixProfilePath -Name "Enabled" -Value 1 -Type DWORD -Force 
# (required setting)
# Type: DWORD
# Default Value: 0
# Data values and use:
# 0: Profile containers disabled.
# 1: Profile containers enabled.

Set-ItemProperty -Path $fslogixProfilePath -Name "VHDLocations" -Value $storagePath -Type MultiString -Force # Added but not 100% sure necessary
# (required setting)
# Type: MULTI_SZ or REG_SZ
# Default Value: N/A
# Data values and use:
# A list of SMB locations to search for the user's profile VHD(x) file. If one isn't found, one is created 
# in the first listed location. If the VHD path doesn't exist, it creates it before it checks if a VHD(x) exists 
# in the path. The path supports the use of the FSLogix custom variables or any environment variables that are 
# available to the user during the sign in process. When specified as a REG_SZ value, multiple locations must be separated with a semi-colon (;).


Set-ItemProperty -Path $fslogixProfilePath -Name "RoamIdentity" -Value 1 -Type DWORD -Force
# 0: Don't roam identity data. (recommended)
# 1: Enables legacy roaming for identity data.
# Under some identity and authentication scenarios, user's may be required to authenticate to their Microsoft 365 applications 
# at every sign-in. Enabling this setting is one way to resolve the issue. We recommend working towards true single sign-on 
# which allows your Windows sign-in to pass its credential to your Microsoft 365 applications.
# Useful references
# https://learn.microsoft.com/en-us/fslogix/troubleshooting-known-issues

Set-ItemProperty -Path $fslogixProfilePath -Name "IsDynamic" -Value 1 -Type DWORD -Force
# Type: DWORD
# Default Value: 1
# Data values and use:
# 0: VHD(x) is of a fixed size and the size on disk is fully allocated.
# 1: VHD(x) is dynamic and only increases the size on disk as necessary.

Set-ItemProperty -Path $fslogixProfilePath -Name "DeleteLocalProfileWhenVHDShouldApply" -Value 1 -Type DWORD -Force
# Type: DWORD
# Default Value: 0
# Data values and use:
# 0: No action.
# 1: Deletes local profile if it exists and matches the profile container.

# NO SUCH REGISTRY SETTING 
# Set-ItemProperty -Path $fslogixProfilePath -Name "RoamMSALCache" -Value 1 -Type DWORD -Force

# Set-ItemProperty -Path $fslogixProfilePath -Name "RoamSearch" -Value 1 -Type DWORD -Force
# OBSOLETE There are no override settings to enable the FSLogix search roaming when it's automatically disabled through Windows version detection.
# Type: DWORD
# Default Value: 0
# Data values and use:
# 0: Disabled.
# 1: Enable single-user search.
# 2: Enable multi-user search.
#

if (!(Test-Path $fslogixODFCPath)) { 
    New-Item -Path "HKLM:\SOFTWARE\FSLogix" -ErrorAction SilentlyContinue
    New-Item -Path $fslogixODFCPath -Force 
}
Set-ItemProperty -Path $fslogixODFCPath -Name "VolumeType" -Type String -Value "vhdx" -Force
# Type: REG_SZ
# Default Value: vhd
# Data values and use:
# A value of vhd means that newly created files should be of type VHD. A value of vhdx means that newly created files should be of type VHDX.

Set-ItemProperty -Path $fslogixODFCPath -Name "Enabled" -Value 1 -Type DWORD -Force
# (required setting)
# Type: DWORD
# Default Value: 0
# Data values and use:
# 0: ODFC containers disabled.
# 1: ODFC containers enabled


Set-ItemProperty -Path $fslogixODFCPath -Name "RoamIdentity" -Value 1 -Type DWORD -Force
# Not sure this exists under ODFC Path - the one in the main FSLogix path appears to be the old/less supported way to get around
# the situation where you're not logging in as the licensed Office user.

Set-ItemProperty -Path $fslogixODFCPath -Name "IncludeOfficeActivation" -Value 1 -Type DWORD -Force
# Type: DWORD
# Default Value: 1
# Data values and use:
# 0: Office activation data isn't redirected to the container.


Set-ItemProperty -Path $fslogixODFCPath -Name "IncludeOutlook" -Value 1 -Type DWORD -Force
# Type: DWORD
# Default Value: 1
# Data values and use:
# 0: Outlook data isn't redirected to the container.
# 1: Outlook data is redirected to the container.

# https://learn.microsoft.com/en-sg/answers/questions/5596386/office-apps-need-to-sign-in-again-and-again-at-eve
# The RoamIdentity setting is not working.
# FRX version 3.25.822.19044

# Force Cloud Kerberos for Azure Files (Entra ID Join Only)
# This is a critical fix that prevented avdprofiles from working and was the last thing fixed to make it work
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (!(Test-Path $lsaPath)) { New-Item $lsaPath -Force }
Set-ItemProperty -Path $lsaPath -Name "CloudKerberosTicketRetrievalEnabled" -Value 1 -Type DWORD -Force
# Enable the Microsoft Entra Kerberos functionality on the client machine(s) you want to mount/use Azure File shares from.
# You must do this on every client on which Azure Files will be used.
# Changes aren't instant, and require a policy refresh or a reboot to take effect

# Restart the FSLogix Service to ingest the new Registry Keys
Write-Host "Restarting FSLogix Service to apply new configuration..."
Restart-Service -Name frxsvc -Force


# --- 1.3 SSD PROVISIONING (Merged Logic) ---
Write-Host "Provisioning Local NVMe SSD..."
try {
    # Find the NVMe disk by name rather than index number
    $nvmeDisk = Get-Disk | Where-Object { $_.FriendlyName -like "*NVMe Direct Disk*" -or $_.Model -like "*Virtual Disk*" -and $_.Size -lt 200GB -and $_.Number -ne 0 }
    
    if ($null -eq $nvmeDisk) { $nvmeDisk = Get-Disk -Number 1 } # Fallback

    if ($nvmeDisk.PartitionStyle -eq 'Raw') {
        Initialize-Disk -Number $nvmeDisk.Number -PartitionStyle GPT
        Write-Host "Disk $($nvmeDisk.Number) Initialized."
    }

    if (!(Get-Partition -DiskNumber $nvmeDisk.Number | Where-Object { $_.DriveLetter -eq 'E' })) {
        New-Partition -DiskNumber $nvmeDisk.Number -UseMaximumSize -DriveLetter E | Format-Volume -FileSystem NTFS -NewFileSystemLabel "LocalSSD_Cache" -Confirm:$false
        Write-Host "Partition E: created."
    }
    
    if (!(Test-Path "E:\TaxDomeCache")) { New-Item -Path "E:\TaxDomeCache" -ItemType Directory -Force }
} catch {
    Write-Warning "SSD Provisioning failed: $($_.Exception.Message)"
}

# --- 1.3 PAGEFILE SETUP ---
Write-Host "Setting 16GB Pagefile on E:..."
try {
    $PageSize = [uint32]16384
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem
    Set-CimInstance -InputObject $ComputerSystem -Property @{AutomaticManagedPagefile = $False}
    Get-CimInstance Win32_PageFileSetting | Remove-CimInstance -ErrorAction SilentlyContinue
        New-CimInstance -ClassName Win32_PageFileSetting -Property @{
        Name = "E:\pagefile.sys"; 
        InitialSize = $PageSize; 
        MaximumSize = $PageSize
    }
} catch { Write-Warning "Pagefile setup failed: $($_.Exception.Message)" }

# 1.3.5 Network & AppX Fixes
# Disabling this as it's unclear this is a current setting or what led to this suggestions
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "GpNetworkStartTimeoutPolicyValue" -Value 60 -Type DWORD -Force

$AppxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
if (-not (Test-Path $AppxPath)) { New-Item -Path $AppxPath -Force }
Set-ItemProperty -Path $AppxPath -Name "AllowDeploymentInSpecialProfiles" -Value 1 -Type DWORD -Force

# 1.3 System Basics: Timezone & Chrome
Set-TimeZone -Id "Pacific Standard Time"
$ChromeUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
$InstallerPath = "$env:TEMP\ChromeInstaller.exe"
Invoke-WebRequest -Uri $ChromeUrl -OutFile $InstallerPath
Start-Process -FilePath $InstallerPath -ArgumentList "/silent", "/install" -Wait
Remove-Item $InstallerPath -Force

# 1.4 Set Chrome as Default
$XmlPath = "$env:SystemDrive\AppAssociations.xml"
@"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
</DefaultAssociations>
"@ | Out-File -FilePath $XmlPath -Encoding UTF8
Dism /Online /Import-DefaultAppAssociations:$XmlPath

# --- 1.4.2 Bloatware removal & UI Customization ---
Write-Host "----------------------------------------------------------------"
Write-Host "Starting Master Cleanup and UI Customization"

# 1. BLOATWARE REMOVAL
$packagesToRemove = @(
    "Microsoft.Teams", "Microsoft.MicrosoftStickyNotes", "Microsoft.Copilot",
    "Microsoft.Getstarted", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote", "Microsoft.People", "Microsoft.SkypeApp",
    "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "*Xbox*",
    "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo",
    "Microsoft.WebMediaExtensions", "Clipchamp.Clipchamp", "Microsoft.BingNews",
    "Microsoft.BingWeather", "Microsoft.OutlookForWindows", "Microsoft.BingSearch",
    "Microsoft.WidgetsPlatformRuntime"
)

foreach ($package in $packagesToRemove) {
    Write-Host "Processing AppX: $package"
    try {
        $provList = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $package -or $_.PackageName -like $package }
        foreach ($prov in $provList) {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
        }
        $instList = Get-AppxPackage -Name $package -AllUsers
        foreach ($inst in $instList) {
            Remove-AppxPackage -Package $inst.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        }
    } catch { Write-Warning "Could not fully remove $package" }
}


# 2. DISABLE WINDOWS FEATURES
$features = @("WindowsMediaPlayer", "WorkFolders-Client")
foreach ($feature in $features) {
    Write-Host "Disabling Feature: $feature"
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
}

# 3. REGISTRY HARDENING & GALLERY REMOVAL
# Doubtful that there's a supported way to disable the Gallery
# Commenting out this code for now.
# Write-Host "Applying Registry Tweaks and Hiding Gallery..."
# $GalleryPath = "HKLM:\SOFTWARE\Classes\CLSID\{e88865ad-11a6-40f3-969d-762f0e0c9c41}\ShellFolder"
# if (Test-Path $GalleryPath) {
#     Set-ItemProperty -Path $GalleryPath -Name "Attributes" -Value 2962227469 -Type DWord 
# }

$regSettings = @(
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1),
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1)
)
foreach ($set in $regSettings) {
    if (!(Test-Path $set[0])) { New-Item -Path $set[0] -Force | Out-Null }
    Set-ItemProperty -Path $set[0] -Name $set[1] -Value $set[2] -Type DWORD
}

# Completely Disable the Widgets/News/Weather Platform UI
$dshPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
if (!(Test-Path $dshPath)) { New-Item -Path $dshPath -Force | Out-Null }
Set-ItemProperty -Path $dshPath -Name "AllowNewsAndInterests" -Value 0 -Type DWORD -Force

# Disable the "Chat" icon (Teams Consumer) while we're at it
$tbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $tbPath)) { New-Item -Path $tbPath -Force | Out-Null }
Set-ItemProperty -Path $tbPath -Name "ConfigureChatIcon" -Value 3 -Type DWORD -Force

# Prevent OneDrive from installing for every new user
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Value "" -ErrorAction SilentlyContinue

# 4. DRIVE SHORTCUTS WITH ICONS
$iconFolder = "C:\ProgramData\KCEA\Icons"
if (!(Test-Path $iconFolder)) { New-Item -Path $iconFolder -ItemType Directory -Force | Out-Null }

$kIconUrl = "https://raw.githubusercontent.com/taxeskcea/public/main/K.ico"
$zIconUrl = "https://raw.githubusercontent.com/taxeskcea/public/main/Z.ico"

try {
    Invoke-WebRequest -Uri $kIconUrl -OutFile "$iconFolder\K.ico" -TimeoutSec 30
    Invoke-WebRequest -Uri $zIconUrl -OutFile "$iconFolder\Z.ico" -TimeoutSec 30
} catch { Write-Warning "Failed to download icons." }

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
}

Write-Host "Cleanup and Customization Complete."

# --- 1.4.5: HEADLESS APP INSTALLATION (WINGET) ---
Write-Host "Searching for Winget Path..."

# Resolve the actual path to winget.exe (which is an App Execution Alias)
$wingetPath = Get-ChildItem -Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller*_x64*\winget.exe" | Select-Object -ExpandProperty FullName -First 1

if ($wingetPath) {
    Write-Host "Winget found at: $wingetPath"

    Write-Host "Starting Winget App Installation..."

    # Winget can sometimes struggle in the SYSTEM context without a defined path
    $env:Path += ";C:\Program Files\WindowsApps"

    # Using the full path to update source since 'winget' alias isn't reliable yet
    & $wingetPath source update --force

    # This has not worked. Only Karen needs this anyway.
    # "Dropbox.Dropbox.MSI",   # Enterprise version
    # Remove Adobe for now as new Adobe for Teams licensing model may not be happy with it.
    # "Adobe.Acrobat.Reader.64-bit", # After signing in, this will upgrade to Acrobat Pro 

    $wingetApps = @(
        "Microsoft.PowerShell",
        "9N040SRQ0S8C",          # Keeper
        "GitHub.GitHubDesktop",
        "Microsoft.Sysinternals.Suite"
    )

    foreach ($app in $wingetApps) {
        Write-Host "Installing: $app..."
            # Using the full path ensures SYSTEM context finds the executable
            $process = Start-Process -FilePath $wingetPath -ArgumentList "install --id $app --silent --accept-package-agreements --accept-source-agreements --scope machine" -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            Write-Warning "Installation of $app failed with code $($process.ExitCode)."
        } else {
            Write-Host "Successfully installed $app."
        }
    } # End of Foreach
} # End of If ($wingetPath)
else {
    Write-Error "Winget executable not found. Skipping app installations."
}



# --- 1.4.7: INSTALL MICROSOFT 365 APPS VIA ODT ---
########## DISBALED ########## Write-Host "Installing Microsoft 365 Apps..."
$odtPath = "$env:TEMP\ODT"
########## DISBALED ########## if (!(Test-Path $odtPath)) { New-Item $odtPath -ItemType Directory }

# 1. Download the Office Deployment Tool
$odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4450/officedeploymenttool_17328-20162.exe"
########## DISBALED ########## Invoke-WebRequest -Uri $odtUrl -OutFile "$odtPath\odt.exe"

# 2. Extract it
########## DISBALED ########## Start-Process -FilePath "$odtPath\odt.exe" -ArgumentList "/extract:$odtPath /quiet" -Wait

# 3. Create a Configuration XML (Standard Business/Enterprise Apps)
$xmlContent = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Bing" />
    </Product>
  </Add>
  <Updates Enabled="TRUE" />
  <RemoveMSI />
  <Display Level="None" AcceptEULA="TRUE" />
</Configuration>
"@
########## DISBALED ########## $xmlContent | Out-File -FilePath "$odtPath\installConfig.xml" -Encoding ascii

# 4. Run the installation
########## DISBALED ########## Write-Host "Running Office Installation (this may take 10-15 minutes)..."
########## DISBALED ########## Start-Process -FilePath "$odtPath\setup.exe" -ArgumentList "/configure $odtPath\installConfig.xml" -Wait
########## DISBALED ########## Write-Host "Microsoft 365 Apps installed successfully."

# --- 1.4.8: MICROSOFT 365 APPS (OFFICE) CONFIGURATION ---
########## DISBALED ########## Write-Host "Configuring pre-installed Microsoft 365 Apps for AVD..."

# Set Shared Computer Licensing (Ensures compliance for the pre-installed suite)
$OfficeRegPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
if (!(Test-Path $OfficeRegPath)) { New-Item -Path $OfficeRegPath -Force | Out-Null }

# SharedComputerLicensing - should be aligned to the configuration.xml launched for office install.
Set-ItemProperty -Path $OfficeRegPath -Name "SharedComputerLicensing" -Value 1 -Type String -Force
# https://learn.microsoft.com/en-us/microsoft-365-apps/licensing-activation/overview-shared-computer-activation
# Option 2: Use Registry Editor to enable shared computer activation
# Use Registry Editor to add a String value (Reg_SZ) of SharedComputerLicensing with a setting of 1 
# under HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration.

# Impoortant to verify how we end up per these instructions
# https://learn.microsoft.com/en-us/microsoft-365-apps/licensing-activation/troubleshoot-shared-computer-activation#Enabled

Write-Host "Office configuration applied."

# --- REGION 2: USER-CONTEXT DRIVE MAPPING (Kerberos Mode) ---
# Drop this script onto the disk to be executed by the user at logon.
$UserScriptPath = "C:\ProgramData\KCEA\UserLogonTasks.ps1"

# Using single quotes for the here-string to prevent variable expansion
$UserScriptContent = @'

# --- PART A: K DRIVE MAPPING ---
$DriveLetter = "K:"
$UNC = "\\kceafiles.file.core.windows.net\kcea"
$MaxRetries = 5
$RetryCount = 0

# 1. Wait up to 30 seconds for Kerberos to be ready
$timeout = 30
while (!(klist | Select-String "kceafiles") -and $timeout -gt 0) {
    Write-Output "Waiting for Kerberos to be ready (T-minus: $timeout)"
    Start-Sleep -Seconds 2
    $timeout -= 2
}

$CleanLetter = $DriveLetter.TrimEnd(':')

while ($RetryCount -lt $MaxRetries) {
    # Check if the drive is already mapped
    if (-not (Get-PSDrive -Name $CleanLetter -ErrorAction SilentlyContinue)) {
        try {
            Write-Output "Attempting to map $DriveLetter to $UNC (Attempt $($RetryCount + 1))..."
            # Attempt to map
            # net use $DriveLetter $UNC /persistent:yes
            # Using New-PSDrive with -Persist is more robust for Entra ID sessions
            New-PSDrive -Name $CleanLetter -PSProvider FileSystem -Root $UNC -Persist -Scope Global -ErrorAction Stop
            
            Write-Output "Successfully mapped $DriveLetter drive."
            break # Exit the loop on success
        } 
        catch {
                $RetryCount++
            Write-Warning "Mapping failed: $($_.Exception.Message)"
            if ($RetryCount -lt $MaxRetries) {
                Write-Output "Retrying in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }
    } 
    else {
        Write-Output "$DriveLetter drive is already mapped."
        break
    }
}

# --- PART B: TAXDOME SSD CACHE & JUNCTION ---
$cachePath = "E:\TaxDomeCache\$env:USERNAME"
$appDataTaxDome = "$env:APPDATA\TaxDome"

# 1. Ensure the folder exists on the volatile E: drive
if (!(Test-Path $cachePath)) {
    New-Item -ItemType Directory -Path $cachePath -Force | Out-Null
}

# 2. Handle the Junction Link
if (Test-Path $appDataTaxDome) {
    $item = Get-Item $appDataTaxDome
    if ($item.Attributes -notmatch "ReparsePoint") {
        # It's a real folder, back it up and link it
        $backup = $appDataTaxDome + "_bak"
        if (!(Test-Path $backup)) { Move-Item -Path $appDataTaxDome -Destination $backup -Force }
        cmd /c mklink /j "$appDataTaxDome" "$cachePath"
    }
} else {
    # No folder exists, just create the link
    cmd /c mklink /j "$appDataTaxDome" "$cachePath"
}
'@

$UserScriptContent | Out-File -FilePath $UserScriptPath -Encoding ascii -Force

# --- REGION 3: CREATE LOGON TRIGGER ---
# Ensures Region 2 runs whenever user logs in.
$TaskName = "AVD-User-Logon-Tasks"
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }

$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File $UserScriptPath"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force

Write-Host "AVD Provisioning Complete."


# --- Enable "Get latest updates as soon as they are available" ---
# --- WINDOWS UPDATE OPTIMIZATION ---
Write-Host "Optimizing Windows Update Settings..."

$wuAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $wuAUPath)) { New-Item -Path $wuAUPath -Force }

# 1. Enable updates for other Microsoft products (Microsoft Update)
Set-ItemProperty -Path $wuAUPath -Name "AllowMUUpdateService" -Value 1 -Type DWORD -Force

# 2. Set Active Hours (Example: 7 AM to 10 PM)
# This prevents reboots during the work day
$wuSettingsPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
if (!(Test-Path $wuSettingsPath)) { New-Item -Path $wuSettingsPath -Force }
Set-ItemProperty -Path $wuSettingsPath -Name "ActiveHoursStart" -Value 7 -Type DWORD -Force
Set-ItemProperty -Path $wuSettingsPath -Name "ActiveHoursEnd" -Value 22 -Type DWORD -Force
Set-ItemProperty -Path $wuSettingsPath -Name "IsUserSpecifiedActiveHoursAllowed" -Value 1 -Type DWORD -Force

# 3. Disable "Optional Updates" notifications to keep UI clean for users
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetUpdateNotificationLevel" -Value 0 -Type DWORD -Force

# Trigger a background update scan immediately
Usoclient.exe StartScan

# Give the Update Orchestrator 30 seconds to reach out to servers and start downloads
# It may not finish, but it will get things started and resume after reboot
Start-Sleep -Seconds 30


# Credential management for split domain
# --- IDENTITY FIXES FOR GODADDY / SPLIT TENANT ---
$OfficeIdentityPath = "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\identity"
if (!(Test-Path $OfficeIdentityPath)) { New-Item -Path $OfficeIdentityPath -Force }

# 1. Allow the user to sign into Office with an account DIFFERENT than the Windows login
Set-ItemProperty -Path $OfficeIdentityPath -Name "DisableADALatopWAMOverride" -Value 0 -Type DWORD -Force

# 2. Disable AAD Auto-Activation (Prevents it from guessing the @onmicrosoft account)
Set-ItemProperty -Path $OfficeIdentityPath -Name "DisableAADAutoActivation" -Value 1 -Type DWORD -Force

# Prevent Windows from trying to 'help' with the wrong Entra ID account
########## DISBALED ########## Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "WebAccountManager" -Value 1 -Type DWORD -Force

# --- ADOBE PERSONAL LICENSE PERSISTENCE ---
$AdobePaths = @(
    "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown",
    "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"
)

foreach ($path in $AdobePaths) {
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    # Disable the "Sign out when browser closes" behavior
    Set-ItemProperty -Path $path -Name "bToggleCustomAuth" -Value 1 -Type DWORD -Force
}


# --- ADOBE ACROBAT SECURITY CUSTOMIZATION ---
$AdobeLockdownPaths = @(
    "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown",
    "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"
)

foreach ($path in $AdobeLockdownPaths) {
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    
    # 1. KEEP Protected Mode ON - Seems to be supported by TTC, but AppContainer should be off.
    # https://tictiecalculate.zendesk.com/hc/en-us/articles/40811230517267-Enable-Protected-Mode-Pre-Requisite
    Set-ItemProperty -Path $path -Name "bProtectedMode" -Value 1 -Type DWORD -Force
    
    # 2. TURN OFF Run in AppContainer
    # This prevents the secondary AppContainer sandbox while keeping the primary Protected Mode active
    Set-ItemProperty -Path $path -Name "bEnableProtectedModeAppContainer" -Value 0 -Type DWORD -Force
    
    # 3. Disable "New Acrobat" UI 
    Set-ItemProperty -Path $path -Name "bEnableAV2Enterprise" -Value 0 -Type DWORD -Force
}

Write-Host "Adobe Security Configured: Protected Mode ON, AppContainer OFF, New UI OFF."



# Removing this one as I don't think it's a current problem (TPM error was earlier in deployment testing, and Gemini suggested this for
# 1) DPAPI / Entra ID Protection Fix
# 2) Critical for remembering passwords/tokens in a non-native Entra environment
# $cryptoPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb"
# if (!(Test-Path $cryptoPath)) { New-Item $cryptoPath -Force }
# Set-ItemProperty -Path $cryptoPath -Name "ProtectionPolicy" -Value 1 -Type DWORD -Force
# Microsoft 365 Apps activation error: “Trusted Platform Module malfunctioned”
# When you try to activate Microsoft 365 apps, you encounter the error:
# ... Trusted Platform Module malfunctioned
# https://learn.microsoft.com/en-us/troubleshoot/microsoft-365-apps/activation/tpm-malfunctioned

# Removing this one as initial set up should not have conflicting/cached credentials that need to be cleared.
# This seems more appropriate for troubleshooting after the initial base install.
# Clear System-level identity stubs to prevent Token Broker loops
# Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force



# Cosmetic Adjustments
# Delete the Edge Shortcut from the Public Desktop
$EdgeShortcut = "C:\Users\Public\Desktop\Microsoft Edge.lnk"
if (Test-Path $EdgeShortcut) {
    Remove-Item -Path $EdgeShortcut -Force
    Write-Host "Removed Microsoft Edge icon from Public Desktop."
}

# Prevent Edge from recreating the desktop shortcut on update
$edgeUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
if (!(Test-Path $edgeUpdatePath)) { New-Item -Path $edgeUpdatePath -Force }
Set-ItemProperty -Path $edgeUpdatePath -Name "CreateDesktopShortcutDefault" -Value 0 -Type DWORD -Force

# Close the log so it is saved and readable
Stop-Transcript

# Trigger the background timer (60 seconds is the sweet spot)
# /r = reboot, /f = force apps closed, /t 60 = 60s delay, /c = comment for the event log
& shutdown.exe /r /f /t 60 /c "AVD Provisioning complete. Rebooting to apply system changes."

# Explicitly exit with code 0 (Success) to tell Azure everything is perfect
exit 0