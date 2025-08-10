# Data Processor Package

This package contains various data processing tools for the Python Excel
Processor project.

## Components

- `main.py` - Main application entry point
- `analyzer.py` - Data analysis functions
- `excel_utils.py` - Excel formatting utilities
- `visualizer.py` - Data visualization utilities
- `batch_cli.py` - CLI for batch processing
- `batch_processor.py` - Batch processing for large datasets
- `password_extractor.py` - Tool for extracting passwords and CTF flags from CSV
  data

## Password Extractor

The password extractor tool is designed to find potential credentials, and token
strings in large CSV datasets.

### Usage

```bash
# Basic usage
poetry run password-extract --input-dir INPUT_DIRECTORY --output-dir OUTPUT_DIRECTORY

# Process raw CSV files rather than processed data
poetry run password-extract --input-dir INPUT_DIRECTORY --output-dir OUTPUT_DIRECTORY --raw-files

# Limit processing to a specific number of files
poetry run password-extract --input-dir INPUT_DIRECTORY --output-dir OUTPUT_DIRECTORY --max-files 1

# Enable verbose logging
poetry run password-extract --input-dir INPUT_DIRECTORY --output-dir OUTPUT_DIRECTORY --verbose
```

### Output

The tool generates several output files:

- `potential_credentials_TIMESTAMP.csv` - Discovered credentials in CSV format
- `token_strings_TIMESTAMP.csv` - Token strings that could be encoded
  credentials
- `password_extraction_summary_TIMESTAMP.md` - Summary report in Markdown format
