# ==============================================================================
# KCEA AVD SMART VERIFIER (Universal Context)
# ==============================================================================
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$IsSystem = ($CurrentIdentity -eq "NT AUTHORITY\SYSTEM")

Write-Host "--- AVD Health Check ---" -ForegroundColor Cyan
Write-Host "Running as: $CurrentIdentity" -ForegroundColor DarkGray

# ------------------------------------------------------------------------------
# REGION 1: SYSTEM CHECKS (Visible to everyone)
# ------------------------------------------------------------------------------
Write-Host "`n[1/3] System Infrastructure..." -ForegroundColor Gray

# Disk Check
$nvmeDisk = Get-Disk | Where-Object { $_.FriendlyName -like "*NVMe Direct Disk*" -or ($_.Model -like "*Virtual Disk*" -and $_.Size -lt 200GB) }
if ($nvmeDisk) {
    $partition = Get-Partition -DiskNumber $nvmeDisk.Number | Where-Object { $_.DriveLetter -eq "E" }
    if ($partition) { Write-Host "  [OK] Local SSD (E:) provisioned." -ForegroundColor Green }
}

# Pagefile Check
$pageFile = Get-CimInstance Win32_PageFileUsage | Where-Object { $_.Name -like "E:*" }
if ($pageFile) { Write-Host "  [OK] Pagefile active on E:." -ForegroundColor Green }

# FSLogix Service & ODFC Check (Visible to SYSTEM and User)
if (Get-Service frxsvc -ErrorAction SilentlyContinue) {
    $frxStatus = & frx list-redirects
    if ($frxStatus -like "*ODFC*") {
        Write-Host "  [OK] ODFC Container is active/configured." -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# REGION 2: USER CONTEXT CHECKS
# ------------------------------------------------------------------------------
Write-Host "`n[2/3] User Environment..." -ForegroundColor Gray

if ($IsSystem) {
    Write-Host "  [SKIP] System context cannot see User Drives or AppData." -ForegroundColor DarkGray
} else {
    # TaxDome Junction
    $appDataTaxDome = "$env:APPDATA\TaxDome"
    if (Test-Path $appDataTaxDome) {
        $item = Get-Item $appDataTaxDome
        if ($item.Attributes -match "ReparsePoint") {
            Write-Host "  [OK] TaxDome Junction: $appDataTaxDome -> $($item.Target)" -ForegroundColor Green
        }
    }

    # K: Drive
    if (Get-PSDrive -Name "K" -ErrorAction SilentlyContinue) {
        Write-Host "  [OK] K: Drive mapped." -ForegroundColor Green
    } else {
        Write-Warning "  [FAIL] K: Drive missing for user."
    }

    # Office Identity Token Broker
    $IdentityPath = "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker"
    if (Test-Path $IdentityPath) {
        Write-Host "  [OK] Identity Token Broker folder exists." -ForegroundColor Green
    } else {
        Write-Warning "  [FAIL] Identity folder missing (Office may prompt)."
    }
}

# ------------------------------------------------------------------------------
# REGION 3: LOGS (Always visible)
# ------------------------------------------------------------------------------
Write-Host "`n[3/3] Provisioning Logs..." -ForegroundColor Gray
$logDir = "C:\ProgramData\KCEA\Logs"
if (Test-Path $logDir) {
    $latestLog = Get-ChildItem -Path $logDir -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestLog) {
        Write-Host "  Latest: $($latestLog.Name) ($($latestLog.LastWriteTime))" -ForegroundColor Yellow
        Get-Content $latestLog.FullName -Tail 5 | Write-Host -ForegroundColor DarkGray
    }
}

Write-Host "`n--- Verification Complete ---" -ForegroundColor Cyan