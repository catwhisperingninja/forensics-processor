# Utility Scripts

This directory contains utility scripts for the Python Excel Processor project.

## Scripts

- `process_large_csv.py` - Splits large CSV files into smaller chunks of 500,000
  rows each.

## Prerequisites

- Use Poetry to manage dependencies: `poetry install`
- Required Python packages (installed via Poetry): `pandas`, `openpyxl` (for
  Excel output), `numpy`
- Optional: `psutil` (only used when running in diagnostic mode)

## Defaults and I/O

- CSV splitter CLI (`csv-split`):
  - Default max rows per output file: 500000
  - Default output prefix: derived from the input filename with `"_split"`
    suffix
  - Default output location: same directory as the input file, files named like
    `<name>_split-1.csv`, `<name>_split-2.csv` (and `*.xlsx` if `--excel` is
    set)
- Helper script (`scripts_forensic/process_large_csv.py`):
  - Default input directory scanned:
    `500k-csv-splits/batch_analysis/csv_output/categorical`
  - It splits any CSV over 500000 rows and writes the outputs alongside the
    original file with `"_split-<n>.csv"` names
  - Excel output is disabled by default for very large files

## Usage

To use the CSV splitter script:

```bash
poetry run csv-split --input <path/to/file.csv> --threshold 500000
```

Alternatively, you can call the script directly:

```bash
poetry run python scripts_forensic/process_large_csv.py --input <path/to/file.csv> --threshold 500000
```

This will check CSV files and split any larger than 500,000 rows into multiple
files.
