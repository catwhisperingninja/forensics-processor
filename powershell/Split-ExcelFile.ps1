param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPrefix,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRowsPerFile = 20000,
    
    [Parameter(Mandatory=$false)]
    [switch]$KeepTempFile = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseSavedTempFile = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$ChunkSize = 5000,
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceKillExcel,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseAlternateMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$DiagnosticMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$EmergencyMode
)

# Emergency mode with ImportExcel module (without COM objects)
if ($EmergencyMode) {
    Write-Host "EMERGENCY MODE - Using ImportExcel module"
    
    # Check if ImportExcel module is installed
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        try {
            Write-Host "Installing ImportExcel module..."
            Install-Module -Name ImportExcel -Scope CurrentUser -Force
        } catch {
            Write-Error "Failed to install ImportExcel module"
            exit 1
        }
    }
    
    # Import the module
    Import-Module ImportExcel
    
    # Validate file exists
    $fullPath = [System.IO.Path]::GetFullPath($InputFile)
    if (-not (Test-Path $fullPath)) {
        Write-Error "File not found"
        exit 1
    }
    
    # Create output prefix if not specified
    if (-not $OutputPrefix) {
        $OutputPrefix = [System.IO.Path]::GetFileNameWithoutExtension($fullPath) + "_split"
    }
    
    try {
        # Read Excel file
        Write-Host "Reading Excel file (this may take time)..."
        $data = Import-Excel -Path $fullPath
        $totalRows = $data.Count
        Write-Host "Total rows: $totalRows"
        
        # Calculate number of files needed
        $numFiles = [math]::Ceiling($totalRows / $MaxRowsPerFile)
        Write-Host "Will create $numFiles files"
        
        # Split into multiple files
        for ($fileNum = 1; $fileNum -le $numFiles; $fileNum++) {
            $outputPath = "$OutputPrefix-$fileNum.xlsx"
            Write-Host "Creating file $fileNum"
            
            # Calculate which rows go in this file
            $startIdx = ($fileNum - 1) * $MaxRowsPerFile
            $endIdx = [Math]::Min($startIdx + $MaxRowsPerFile - 1, $totalRows - 1)
            
            # Get the rows for this file
            $chunk = $data[$startIdx..$endIdx]
            
            # Export to Excel
            $chunk | Export-Excel -Path $outputPath -AutoSize
            Write-Host "Exported $(($endIdx - $startIdx) + 1) rows"
        }
        
        Write-Host "Done! Created $numFiles files"
        exit 0
    } catch {
        Write-Error "Error processing file"
        exit 1
    }
}

if ($DiagnosticMode) {
    Write-Host "=== DIAGNOSTIC MODE ==="
    
    # System info
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
    Write-Host "OS: $([System.Environment]::OSVersion.Version)"
    
    # Excel check
    $excelPath = "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
    $excelExists = Test-Path $excelPath
    Write-Host "Excel found: $excelExists"
    
    # Basic Excel test
    try {
        $excel = New-Object -ComObject Excel.Application
        Write-Host "Excel COM created successfully"
        $excel.Quit()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
    } catch {
        $msg = $_.Exception.Message
        Write-Host "Excel COM failed: $msg"
    }
    
    # Memory
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    Write-Host "Free memory: $freeMemGB GB"
    
    exit 0
}

Write-Host "Executing script with Excel COM automation"
Write-Host "If you encounter errors, try using -EmergencyMode parameter"
Write-Host "For diagnostics, try -DiagnosticMode parameter"
Write-Host "Working with file: $InputFile"

# Force garbage collection
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers() 