
<#
.SYNOPSIS
  Hardened Azure Files drive mapping using Azure AD (Kerberos) without enabling File & Printer Sharing.

.DESCRIPTION
  - Validates environment (TLS 1.2, SMB settings, DNS resolution).
  - Verifies TCP 445 reachability to Azure Files endpoint.
  - Maps drive letter using Azure AD (Kerberos) credentials (no passwords).
  - Adds persistence for the user.
  - Logs actions to %ProgramData%\AVD\Logs.
  - Optionally hides Shutdown option in Start Menu.

.NOTES
  Designed for Azure Virtual Desktop (AVD) session hosts with Azure AD Kerberos enabled.
  Requires user context with valid Azure AD Kerberos tickets.
  Run as regular user (not admin) for drive mapping; admin required for HKLM registry changes.
  Adjust $DriveLetter, $StorageAccount, and $ShareName as needed.
#>

#region Configuration
# share URL https://kceafiles.file.core.windows.net/kcea
$DriveLetter     = 'K:'
$StorageAccount  = 'kceafiles'          # e.g., mystorageacct
$ShareName       = 'kcea'                   # e.g., fileshare
$LogRoot         = 'C:\ProgramData\AVD\Logs'
$LogFile         = Join-Path $LogRoot "MapAzureFiles_AD_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
# Toggle: when $true the Shutdown/Restart/Sleep/Hibernate commands are removed from Start/Power options
$DisableShutdown = $false
# TCP probe timeout in seconds (used to test TCP 445 reachability)
$TcpTimeoutSeconds = 5
#endregion

#region Logging helper
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
function Write-Log { param([string]$Message,[string]$Level='INFO')
  $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
  $line | Tee-Object -FilePath $LogFile -Append
}
#endregion

try {
  Write-Log "Starting Azure Files drive mapping (Azure AD Kerberos)."

  #region Security hardening: enforce TLS 1.2
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Write-Log "SecurityProtocol set to TLS 1.2."
  #endregion

  #region Validate DNS & endpoint
  $fqdn = "$StorageAccount.file.core.windows.net"
  Write-Log "Resolving DNS for $fqdn ..."
  $dns = Resolve-DnsName -Name $fqdn -ErrorAction Stop
  Write-Log "DNS resolved: $($dns | Select-Object -ExpandProperty IPAddress -ErrorAction Ignore | Where-Object { $_ } | ForEach-Object { $_ } | Out-String)"
  #endregion

  #region Check TCP 445 connectivity
  Write-Log "Testing TCP 445 to $fqdn ..."

  function Test-TcpPortWithTimeout {
    param(
      [Parameter(Mandatory=$true)][string]$TargetHost,
      [int]$Port = 445,
      [int]$TimeoutSeconds = 5
    )

    $timeoutMs = [int]($TimeoutSeconds * 1000)
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
      $completed = $iar.AsyncWaitHandle.WaitOne($timeoutMs)
      if (-not $completed) {
        $client.Close()
        return $false
      }
      $client.EndConnect($iar)
      $client.Close()
      return $true
    }
    catch {
      return $false
    }
  }

  # Prefer using the resolved IP address if available to avoid additional DNS delays
  $ipAddress = $null
  try { $ipAddress = ($dns | Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress) } catch { }
  $target = if ($ipAddress) { $ipAddress } else { $fqdn }

  $tcpOk = Test-TcpPortWithTimeout -TargetHost $target -Port 445 -TimeoutSeconds $TcpTimeoutSeconds
  if (-not $tcpOk) {
    throw "TCP 445 to $fqdn (target $target) failed or timed out. Check NSG/Firewall egress rules."
  }
  Write-Log "TCP 445 reachable (target: $target)."
  #endregion

  #region Optional SMB client hardening (Windows defaults are already secure in Win11)
  # Require SMB signing (already default in many cases)
  Write-Log "Ensuring SMB client signing is enabled."
  try {
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    Write-Log "SMB client signing enabled."
  }
  catch {
    Write-Log "Failed to set SMB signing (requires admin privileges): $($_.Exception.Message)" 'WARN'
  }

  # Prefer SMB encryption when supported (Azure Files supports per-share encryption in transit)
  # Client-side toggle not strictly required; Azure enforces encryption in transit.
  Write-Log "SMB client security settings applied."
  #endregion

  #region Clean any stale mapping
  if (Get-PSDrive -Name ($DriveLetter.TrimEnd(':')) -ErrorAction SilentlyContinue) {
    Write-Log "Existing drive $DriveLetter found—removing."
    net use $DriveLetter /delete /y | Out-Null
    Start-Sleep -Seconds 1
  }
  #endregion

  #region Map with Azure AD (Kerberos)
  $unc = "\\$fqdn\$ShareName"
  Write-Log "Attempting to map $DriveLetter to $unc using Azure AD Kerberos."
  # Map the drive (persistent for the user). No credentials passed → Kerberos ticket used.
  $mapCmd = "net use $DriveLetter $unc /persistent:yes"
  Write-Log "Executing: $mapCmd"
  cmd.exe /c $mapCmd | Tee-Object -FilePath $LogFile -Append

  # Verify mapping
  $mapped = Get-PSDrive -Name ($DriveLetter.TrimEnd(':')) -ErrorAction SilentlyContinue
  if (-not $mapped) {
    $errorMsg = "Drive $DriveLetter did not map. This script requires Azure AD Kerberos authentication, which is only available in Azure Virtual Desktop (AVD) environments with Azure Files AD integration enabled. Verify Azure Files AD Kerberos is enabled and user has proper RBAC permissions."
    Write-Log $errorMsg 'ERROR'
    throw $errorMsg
  }
  Write-Log "Drive mapped successfully: $DriveLetter → $unc"
  #endregion

  #region Optional: disable/hide Shutdown in Start Menu (NoClose)
  function Set-NoClosePolicy {
    param(
      [bool]$Disable = $true
    )

    $value = if ($Disable) { 1 } else { 0 }
    $paths = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    foreach ($p in $paths) {
      try {
        New-Item -Path $p -Force | Out-Null
        New-ItemProperty -Path $p -Name 'NoClose' -Value $value -PropertyType DWord -Force | Out-Null
        Write-Log "Set NoClose=$value at $p"
      }
      catch {
        Write-Log "Failed to set NoClose at ${p}: $($_.Exception.Message)" 'WARN'
      }
    }

    # Refresh Explorer to apply immediately for the current user (restarts shell briefly)
    try {
      Write-Log 'Restarting Explorer to apply NoClose policy for current user.'
      Stop-Process -Name explorer -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 1
      Start-Process explorer.exe
    }
    catch {
      Write-Log "Could not restart Explorer: $($_.Exception.Message)" 'WARN'
    }
  }

  if ($DisableShutdown) {
    Write-Log 'Applying shutdown-hide policy (NoClose).'
    Set-NoClosePolicy -Disable $true
  }
  #endregion

  Write-Log "Completed successfully."
}
catch {
  Write-Log "ERROR: $($_.Exception.Message)" 'ERROR'
  throw
}


