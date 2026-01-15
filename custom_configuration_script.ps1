# =================================================================================
# AVD Provisioning Script (System + User Context)
# =================================================================================

# --- REGION 1: SYSTEM-LEVEL SETUP (Runs as SYSTEM) ---
Write-Host "Configuring System Settings and FSLogix Cloud-Only Fixes..."

# 1.1 FSLogix Cloud-Only Stability Keys (Per your Log)
$fslogixPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
if (!(Test-Path $fslogixPath)) { New-Item $fslogixPath -Force }
Set-ItemProperty -Path $fslogixPath -Name "RoamIdentity" -Value 1 -PropertyType DWORD
Set-ItemProperty -Path $fslogixPath -Name "IsDynamic" -Value 1 -PropertyType DWORD
Set-ItemProperty -Path $fslogixPath -Name "DeleteLocalProfileWhenVHDShouldApply" -Value 1 -PropertyType DWORD

# 1.2 Network & AppX Fixes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "GpNetworkStartTimeoutPolicyValue" -Value 60 -PropertyType DWORD
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

$UserScriptContent = @'
$DriveLetter = 'K:'
$UNC = "\\kceafiles.file.core.windows.net\kcea"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Map using the existing Kerberos ticket from the Entra ID login
# NOT using Storage Keys here to avoid Error 1219.
if (-not (Get-PSDrive -Name ($DriveLetter.TrimEnd(':')) -ErrorAction SilentlyContinue)) {
    net use $DriveLetter $UNC /persistent:yes
}
'@
$UserScriptContent | Out-File -FilePath $UserScriptPath -Force

# --- REGION 3: CREATE LOGON TRIGGER ---
# Ensures Region 2 runs whenever user logs in.
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File $UserScriptPath"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -GroupId "Users" -Role Limited
Register-ScheduledTask -TaskName "AVD-User-Logon-Tasks" -Action $Action -Trigger $Trigger -Principal $Principal -Force

Write-Host "AVD Provisioning Complete."
