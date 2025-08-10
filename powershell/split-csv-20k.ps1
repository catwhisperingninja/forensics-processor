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
    [int]$ChunkSize = 5000,

    [Parameter(Mandatory=$false)]
    [switch]$DiagnosticMode
)

# Run diagnostics if requested
if ($DiagnosticMode) {
    Write-Host "=== DIAGNOSTIC MODE ==="

    # System info
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
    Write-Host "OS: $([System.Environment]::OSVersion.Version)"

    # Check ImportExcel module
    $hasImportExcel = Get-Module -ListAvailable -Name ImportExcel
    Write-Host "ImportExcel module found: $($hasImportExcel -ne $null)"

    # Memory
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    Write-Host "Free memory: $freeMemGB GB"

    exit 0
}

# Ensure ImportExcel module is installed
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    try {
        Write-Host "Installing ImportExcel module..."
        Install-Module -Name ImportExcel -Scope CurrentUser -Force
    } catch {
        Write-Error "Failed to install ImportExcel module. Error: $_"
        exit 1
    }
}

# Import the module
Import-Module ImportExcel

# Validate file exists
$fullPath = [System.IO.Path]::GetFullPath($InputFile)
if (-not (Test-Path $fullPath)) {
    Write-Error "Input file not found: $fullPath"
    exit 1
}

# Create output prefix if not specified
if (-not $OutputPrefix) {
    $OutputPrefix = [System.IO.Path]::GetFileNameWithoutExtension($fullPath) + "_split"
}

# Create temp file
$tempFile = $null
$tempName = [System.IO.Path]::GetTempFileName()
$tempFile = [System.IO.Path]::ChangeExtension($tempName, "csv")
Remove-Item $tempName -ErrorAction SilentlyContinue
Copy-Item $fullPath $tempFile

try {
    # Read CSV file
    Write-Host "Reading CSV file: $fullPath"
    $data = Import-Csv -Path $tempFile
    $totalRows = $data.Count
    Write-Host "Total rows: $totalRows"

    # Calculate number of files needed
    $numFiles = [math]::Ceiling($totalRows / $MaxRowsPerFile)
    Write-Host "Will create $numFiles files (both CSV and Excel)"

    # Split into multiple files
    for ($fileNum = 1; $fileNum -le $numFiles; $fileNum++) {
        # Calculate which rows go in this file
        $startIdx = ($fileNum - 1) * $MaxRowsPerFile
        $endIdx = [Math]::Min($startIdx + $MaxRowsPerFile - 1, $totalRows - 1)
        $rowCount = ($endIdx - $startIdx) + 1

        # Base filename (without extension)
        $baseOutputPath = "$OutputPrefix-$fileNum"
        $csvOutputPath = "$baseOutputPath.csv"
        $excelOutputPath = "$baseOutputPath.xlsx"

        Write-Host "Creating file $fileNum ($rowCount rows)"

        # Get the rows for this chunk
        $chunk = $data[$startIdx..$endIdx]

        # Create CSV file
        Write-Host "  Creating CSV: $csvOutputPath"
        $chunk | Export-Csv -Path $csvOutputPath -NoTypeInformation

        # Create Excel file
        Write-Host "  Creating Excel: $excelOutputPath"
        $chunk | Export-Excel -Path $excelOutputPath -AutoSize
    }

    Write-Host "Done! Created $numFiles files of each type (CSV and Excel)"
}
catch {
    Write-Error "Error processing file: $_"
    exit 1
}
finally {
    # Clean up temp file
    if (-not $KeepTempFile -and $tempFile -and (Test-Path $tempFile)) {
        Remove-Item $tempFile -Force
    }

    # Force garbage collection
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
