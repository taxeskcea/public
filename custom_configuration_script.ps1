#region 1. System-Level Setup (Runs as Admin/SYSTEM)
Write-Host "Configuring System Settings..."

# Set Timezone
Set-TimeZone -Id "Pacific Standard Time"

# Install Chrome Silently
$ChromeUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
$InstallerPath = "$env:TEMP\ChromeInstaller.exe"
Invoke-WebRequest -Uri $ChromeUrl -OutFile $InstallerPath
Start-Process -FilePath $InstallerPath -ArgumentList "/silent", "/install" -Wait
Remove-Item $InstallerPath -Force

# Fix FSLogix AppX Registration
$AppxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
if (-not (Test-Path $AppxPath)) { New-Item -Path $AppxPath -Force }
Set-ItemProperty -Path $AppxPath -Name "AllowDeploymentInSpecialProfiles" -Value 1 -Type DWORD -Force

# Set Chrome as Default (System Association)
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
#endregion

#region 2. Prepare the User-Level Mapping Script
# We are embedding your hard-coded mapping script here to be written to the disk
$UserScriptPath = "C:\ProgramData\AVD\MapKDrive.ps1"
if (-not (Test-Path "C:\ProgramData\AVD")) { New-Item -Path "C:\ProgramData\AVD" -ItemType Directory -Force }

$UserScriptContent = @'
# --- YOUR KERBEROS MAPPING SCRIPT START ---
$DriveLetter = 'K:'
$StorageAccount = 'kceafiles'
$ShareName = 'kcea'
$fqdn = "$StorageAccount.file.core.windows.net"
$unc = "\\$fqdn\$ShareName"

# Enforce TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Map drive if not exists
if (-not (Get-PSDrive -Name ($DriveLetter.TrimEnd(':')) -ErrorAction SilentlyContinue)) {
    net use $DriveLetter $unc /persistent:yes
}
# --- YOUR KERBEROS MAPPING SCRIPT END ---
'@

$UserScriptContent | Out-File -FilePath $UserScriptPath -Force
#endregion

#region 3. Create Logon Trigger
# This ensures the mapping script runs in the USER context when Ben or Karen logs in
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File $UserScriptPath"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -GroupId "Users" -Role Limited
Register-ScheduledTask -TaskName "AVD-User-Logon-Tasks" -Action $Action -Trigger $Trigger -Principal $Principal -Force
#endregion

Write-Host "AVD Provisioning Complete."
