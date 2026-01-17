# ==============================================================================
# KCEA AVD PROVISIONING VERIFIER
# ==============================================================================
Write-Host "--- Starting AVD Health Check ---" -ForegroundColor Cyan

# 1. CHECK DISK & PAGING
Write-Host "`n[1/3] Checking SSD & Paging Status..." -ForegroundColor Gray
$nvmeDisk = Get-Disk | Where-Object { $_.FriendlyName -like "*NVMe Direct Disk*" -or ($_.Model -like "*Virtual Disk*" -and $_.Size -lt 200GB) }

if ($nvmeDisk) {
    $partition = Get-Partition -DiskNumber $nvmeDisk.Number | Where-Object { $_.DriveLetter -eq "E" }
    if ($partition) {
        Write-Host "  [OK] Local NVMe SSD (E:) is provisioned and healthy." -ForegroundColor Green
    } else {
        Write-Warning "  [FAIL] NVMe Disk found but Partition E: is missing."
    }
} else {
    Write-Warning "  [FAIL] Local NVMe not found or offline."
}

# Define and check Pagefile
$pageFile = Get-CimInstance Win32_PageFileUsage | Where-Object { $_.Name -like "E:*" }
if ($pageFile -and $pageFile.AllocatedBaseSize -ge 16000) {
    Write-Host "  [OK] Pagefile is active on E: ($($pageFile.AllocatedBaseSize) MB)." -ForegroundColor Green
} else {
    Write-Warning "  [FAIL] Pagefile not found on E: or incorrect size."
}

# 2. CHECK TAXDOME REDIRECTION & K: DRIVE
Write-Host "`n[2/3] Checking User Environment..." -ForegroundColor Gray
$appDataTaxDome = "$env:APPDATA\TaxDome"
if (Test-Path $appDataTaxDome) {
    $item = Get-Item $appDataTaxDome
    if ($item.Attributes -match "ReparsePoint") {
        Write-Host "  [OK] TaxDome Junction is active: $appDataTaxDome -> $($item.Target)" -ForegroundColor Green
    } else {
        Write-Warning "  [WARN] TaxDome folder exists but is NOT a junction."
    }
} else {
    Write-Host "  [INFO] TaxDome AppData not yet created (Normal if first login)." -ForegroundColor Yellow
}

# Quick check for K: Drive
if (Get-PSDrive -Name "K" -ErrorAction SilentlyContinue) {
    Write-Host "  [OK] K: Drive is mapped and accessible." -ForegroundColor Green
} else {
    Write-Warning "  [WARN] K: Drive is not mapped for the current user."
}

# 3. COLLECT & DISPLAY RECENT LOGS
Write-Host "`n[3/3] Fetching Most Recent Provisioning Log..." -ForegroundColor Gray
$logDir = "C:\ProgramData\KCEA\Logs"
if (Test-Path $logDir) {
    $latestLog = Get-ChildItem -Path $logDir -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    if ($latestLog) {
        Write-Host "  Latest Log: $($latestLog.Name) ($($latestLog.LastWriteTime))" -ForegroundColor Yellow
        Write-Host "--- Log Tail (Last 10 Lines) ---" -ForegroundColor DarkGray
        Get-Content $latestLog.FullName -Tail 10
    } else {
        Write-Warning "  No log files found in $logDir."
    }
} else {
    Write-Warning "  Log directory $logDir does not exist."
}

Write-Host "`n--- Verification Complete ---" -ForegroundColor Cyan