# ==============================================================================
# KCEA AVD PROVISIONING VERIFIER
# ==============================================================================
Write-Host "--- Starting AVD Health Check ---" -ForegroundColor Cyan

# 1. CHECK DISK & PAGING
Write-Host "`n[1/3] Checking Disk 1 & Paging Status..." -Gray
$disk1 = Get-Disk -Number 1 -ErrorAction SilentlyContinue
$pageFile = Get-CimInstance Win32_PageFileUsage | Where-Object { $_.Name -like "E:*" }

if ($disk1.OperationalStatus -eq 'Online' -and $disk1.FriendlyName -match "Virtual") {
    Write-Host "  [OK] Local NVMe (Disk 1) is Online." -ForegroundColor Green
} else {
    Write-Warning "  [FAIL] Local NVMe (Disk 1) not found or offline."
}

if ($pageFile.AllocatedBaseSize -ge 16000) {
    Write-Host "  [OK] Pagefile is active on E: ($($pageFile.AllocatedBaseSize) MB)." -ForegroundColor Green
} else {
    Write-Warning "  [FAIL] Pagefile not found on E: or incorrect size. Current: $($pageFile.Name)"
}

# 2. CHECK TAXDOME REDIRECTION (User Context)
Write-Host "`n[2/3] Checking TaxDome Junction..." -Gray
$appDataTaxDome = "$env:APPDATA\TaxDome"
if (Test-Path $appDataTaxDome) {
    $item = Get-Item $appDataTaxDome
    if ($item.Attributes -match "ReparsePoint") {
        Write-Host "  [OK] TaxDome Junction is active: $appDataTaxDome -> $($item.Target)" -ForegroundColor Green
    } else {
        Write-Warning "  [WARN] TaxDome folder exists but is NOT a junction. Cache is hitting the C: drive."
    }
} else {
    Write-Host "  [INFO] TaxDome AppData not yet created (User hasn't launched app or script yet)."
}

# 3. COLLECT & DISPLAY RECENT LOGS
Write-Host "`n[3/3] Fetching Most Recent Provisioning Log..." -Gray
$logDir = "C:\ProgramData\KCEA\Logs"
if (Test-Path $logDir) {
    $latestLog = Get-ChildItem -Path $logDir -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    if ($latestLog) {
        Write-Host "  Latest Log: $($latestLog.Name) ($($latestLog.LastWriteTime))" -ForegroundColor Yellow
        Write-Host "--- Log Tail (Last 10 Lines) ---" -DarkGray
        Get-Content $latestLog.FullName -Tail 10
    } else {
        Write-Warning "  No log files found in $logDir."
    }
} else {
    Write-Warning "  Log directory $logDir does not exist."
}

Write-Host "`n--- Verification Complete ---" -ForegroundColor Cyan