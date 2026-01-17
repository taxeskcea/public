# --- CONFIGURATION ---
$LogDir = "C:\ProgramData\KCEA\Logs"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force }
$LogFile = "$LogDir\ProvisionSSD.log"

function Write-KCEALog {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

Write-KCEALog "Starting SSD Provisioning and TaxDome Setup..."

# 1. DISK PROVISIONING (DISK 1 -> E:)
try {
    $disk = Get-Disk -Number 1
    if ($disk.PartitionStyle -eq 'Raw') { 
        Initialize-Disk -Number 1 -PartitionStyle GPT 
        Write-KCEALog "Disk 1 Initialized as GPT."
    }
    
    $part = Get-Partition -DiskNumber 1 | Where-Object { $_.Type -ne 'Reserved' }
    if (-not $part) {
        New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter E | Format-Volume -FileSystem NTFS -NewFileSystemLabel "LocalSSD_Cache" -Confirm:$false
        Write-KCEALog "Partition E: created and formatted."
    } else {
        Write-KCEALog "Partition E: already exists."
    }
} catch {
    Write-KCEALog "ERROR: Failed during disk provisioning: $($_.Exception.Message)"
}

# 2. TAXDOME CACHE DIRECTORY
if (!(Test-Path "E:\TaxDomeCache")) { 
    New-Item -Path "E:\TaxDomeCache" -ItemType Directory -Force 
    Write-KCEALog "TaxDomeCache folder created on E:."
}

# 3. PAGEFILE SETUP (Casting to uint32 to avoid Type Mismatch)
try {
    $PageSizeMB = [uint32]16384
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem
    if ($ComputerSystem.AutomaticManagedPagefile) {
        Set-CimInstance -InputObject $ComputerSystem -Property @{AutomaticManagedPagefile = $False}
    }
    Get-CimInstance Win32_PageFileSetting | Remove-CimInstance -ErrorAction SilentlyContinue
    New-CimInstance -ClassName Win32_PageFileSetting -Property @{
        Name = "E:\pagefile.sys"; InitialSize = $PageSizeMB; MaximumSize = $PageSizeMB
    }
    Write-KCEALog "Pagefile set to 16GB on E:."
} catch {
    Write-KCEALog "ERROR: Pagefile setup failed: $($_.Exception.Message)"
}

Write-KCEALog "Provisioning script completed."