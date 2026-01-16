# =================================================================================
# AVD Provisioning Script (System + User Context)
# =================================================================================
$LogFile = "C:\ProgramData\AVD_Provisioning.log"
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
$fslogixPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$storagePath = "\\kceafiles.file.core.windows.net\avdprofiles" # Added for 2 new statements in Core FSLogix Config below

$cryptoPath  = "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb" # Added for 2 statements in DPAPI / Entra ID Protection Fix below

if (!(Test-Path $fslogixPath)) { 
    New-Item -Path "HKLM:\SOFTWARE\FSLogix" -ErrorAction SilentlyContinue
    New-Item -Path $fslogixPath -Force 
}
# Core FSLogix Configuration
Set-ItemProperty -Path $fslogixPath -Name "Enabled" -Value 1 -Type DWORD -Force # Added but not 100% sure necessary
Set-ItemProperty -Path $fslogixPath -Name "VHDLocations" -Value $storagePath -Type MultiString -Force # Added but not 100% sure necessary
Set-ItemProperty -Path $fslogixPath -Name "RoamIdentity" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $fslogixPath -Name "IsDynamic" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $fslogixPath -Name "DeleteLocalProfileWhenVHDShouldApply" -Value 1 -Type DWORD -Force

# Force Cloud Kerberos for Azure Files (Entra ID Join Only)
# This is a critical fix that prevented avdprofiles from working and was the last thing fixed to make it work
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (!(Test-Path $lsaPath)) { New-Item $lsaPath -Force }
Set-ItemProperty -Path $lsaPath -Name "CloudKerberosTicketRetrievalEnabled" -Value 1 -Type DWORD -Force


# FSLogix & Identity Hardening # 
# DPAPI / Entra ID Protection Fix
if (!(Test-Path $cryptoPath))  { New-Item $cryptoPath -Force }
Set-ItemProperty -Path $cryptoPath -Name "ProtectionPolicy" -Value 1 -Type DWORD -Force

# 1.2 Network & AppX Fixes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "GpNetworkStartTimeoutPolicyValue" -Value 60 -Type DWORD -Force

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

# --- REGION 2: USER-CONTEXT DRIVE MAPPING (Kerberos Mode) ---
# Drop this script onto the disk to be executed by the user at logon.
$UserScriptPath = "C:\ProgramData\AVD\MapKDrive.ps1"
if (-not (Test-Path "C:\ProgramData\AVD")) { New-Item -Path "C:\ProgramData\AVD" -ItemType Directory -Force }

# Using single quotes for the here-string to prevent variable expansion
$UserScriptContent = @'
$DriveLetter = "K:"
$UNC = "\\kceafiles.file.core.windows.net\kcea"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Map using the existing Kerberos ticket from the Entra ID login
# NOT using Storage Keys here to avoid Error 1219.
if (-not (Get-PSDrive -Name ($DriveLetter.TrimEnd(':')) -ErrorAction SilentlyContinue)) {
    # Using 'net use' is more resilient for Kerberos identity pass-through
    net use $DriveLetter $UNC /persistent:yes
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
$wuPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
if (!(Test-Path $wuPath)) { New-Item -Path $wuPath -Force }

Set-ItemProperty -Path $wuPath -Name "IsAutoUpdateFeaturedControlAllowed" -Value 1 -Type DWORD -Force

# Trigger a background update scan immediately
Usoclient.exe StartScan

Stop-Transcript