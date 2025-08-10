# Windows 11 System Timeline Investigation

This project provides tools for conducting post-Plaso forensic analysis of
browser artifacts and correlating them with system timeline data to identify
suspicious activities.

Assumes previous use of Plaso on SIFT Workstation, and is posted for a limited
period of time.

## This Repo Is Not Actively Developed

After some internal back-and-forth, I'm again publishing this from my archives.
A substantial amount of CodeRabbit improvements have been made.

I have not tested anything, per the heading. But I can assure you that the
report data is no longer merely anonymized: it's totally fake.

## Hilarious Background Story

This was a real-world system I was authorized to investigate.

### TL;DR

If you try REALLY, SUPER hard to keep the security analyst away from the
computers - who has the legal right and authorization to review those
computers -

The security analyst knows for certain that there are juicy findings to be had.
(Not here.)

## Notes

- Any warnings on "exposed secrets" are false positives on ancient Oauth and
  other web browser tokens. Github insists these are AWS secrets.
- The /scripts_forensic/bitcoin_finder.py script returns bad output, often
  mistaking browser tokens and other alphanumeric strings for Bitcoin addresses.
- This could theoretically be fixed with some checksum logic as Bitcoin is very
  specific.
- The one test has some issues.

# Overview

** REPORT DATA IS FULLY SYNTETHIC AND ONLY A SAMPLE OF AVAILABLE OUTPUTS.**

The Windows 11 System Timeline Investigation toolkit enables detailed forensic
analysis of:

1. Browser extensions and their security implications
2. Suspicious URL access patterns and categorization
3. Google Drive document access and sensitive file identification
4. Correlation between browser activities and system events
5. Specialized detection of high-risk artifacts (TeamViewer, cryptocurrency
   wallets)

The toolkit integrates browser-specific analysis with system-wide artifact
examination to create a comprehensive security assessment.

## Project Structure

```
forensics-processor/
├── 500k-sanitized-run_20250330/    # Sanitized sample data run
│   ├── anonymize.py               # Anonymizes sensitive data in JSON files
│   ├── autofill_*.ndjson.gz       # NDJSON.gz synthetic sample (streaming)
│   ├── login_data_*.ndjson.gz     # NDJSON.gz synthetic sample (streaming)
│   └── password_extraction_*.md   # (Removed) Sensitive; do not commit
│
├── powershell/                    # PowerShell utilities for Windows
│   ├── Split-ExcelFile.ps1        # Split Excel files into smaller chunks
│   ├── split-csv-20k.ps1          # Split CSV into 20k row chunks
│   └── split-csv-500k.ps1         # Split CSV into 500k row chunks
│
├── scripts_anonymizers/           # Data anonymization scripts
│   └── anonymize_md.py            # Anonymize Markdown files
│
├── scripts_forensic/              # Core forensic analysis scripts
│   ├── analyze_all_urls.py        # Comprehensive URL analysis
│   ├── bitcoin_finder.py          # Bitcoin address detection (see notes)
│   ├── browser_extension_analyzer.py # Browser extension security analysis
│   ├── cleanup.sh                 # Cleanup temporary files
│   ├── crypto_wallet_detector.py  # Cryptocurrency wallet detection
│   ├── domain_artifact_analyzer.py # Domain-specific artifact analysis
│   ├── google_drive_analyzer.py   # Google Drive activity analysis
│   ├── process_large_csv.py       # Process large CSV files
│   ├── run_bitcoin_search.sh      # Batch Bitcoin search script
│   ├── scriptsREADME.md           # Scripts documentation
│   ├── suspicious_url_analyzer.py # Suspicious URL detection
│   ├── system_timeline_analyzer.py # System timeline analysis
│   ├── teamviewer_detector.py     # TeamViewer activity detection
│   └── timeline_correlation.py    # Correlate browser/system events
│
├── scripts_github_de-blocker/     # GitHub secret removal utilities
│   ├── sanitize_forensics.py      # Sanitize forensic data
│   └── sanitize_tokens.py         # Remove/sanitize tokens
│
├── src/data_processor/            # Core data processing modules
│   ├── analyzer.py                # Data analysis engine
│   ├── batch_cli.py               # Batch processing CLI
│   ├── batch_processor.py         # Batch processing logic
│   ├── credential_analyzer.py     # Credential analysis
│   ├── credential_cli.py          # Credential analysis CLI
│   ├── credential_risk_analyzer.py # Credential risk assessment
│   ├── credential_risk_cli.py     # Risk analysis CLI
│   ├── csv_split_cli.py           # CSV splitting CLI
│   ├── csv_splitter.py            # CSV splitting logic
│   ├── excel_utils.py             # Excel file utilities
│   ├── main.py                    # Main entry point
│   ├── password_extractor.py      # Password extraction logic
│   ├── password_extractor_cli.py  # Password extraction CLI
│   ├── post_processor.py          # Post-processing utilities
│   ├── srcREADME.md               # Module documentation
│   └── visualizer.py              # Data visualization
│
├── tests/                         # Test suite
│   ├── test_default_workflow/     # Default workflow tests
│   └── parsers.txt                # Test parser configurations
│
├── process_large_csv.py           # Root-level CSV processor
├── pyproject.toml                 # Poetry project configuration
├── poetry.lock                    # Poetry dependency lock file
├── run_all_analysis.sh            # Master analysis orchestrator
└── README.md                      # This file
```

### Key Components Explained

#### `run_all_analysis.sh`

Master orchestration script that runs the complete forensic analysis pipeline:

1. Creates output directory structure
2. Runs system timeline analysis
3. Performs TeamViewer detection
4. Searches for cryptocurrency wallets
5. Correlates browser activity with system timeline
6. Generates executive summary

#### PowerShell Scripts (`/powershell`)

Windows-specific utilities for handling large datasets:

- **Split-ExcelFile.ps1**: Splits large Excel files into manageable chunks
- **split-csv-20k.ps1**: Creates 20,000-row CSV chunks (for detailed analysis)
- **split-csv-500k.ps1**: Creates 500,000-row CSV chunks (for bulk processing)

#### Data Processing Pipeline (`/src/data_processor`)

Core Python modules for data manipulation:

- **analyzer.py**: Main analysis engine for Excel/CSV data
- **batch_processor.py**: Handles processing of multiple files
- **credential\_\*.py**: Specialized credential and password analysis
- **csv_splitter.py**: Python-based CSV splitting (cross-platform)
- **visualizer.py**: Creates charts and visualizations

#### Forensic Scripts (`/scripts_forensic`)

Specialized analysis tools:

- **URL Analysis**: `analyze_all_urls.py`, `suspicious_url_analyzer.py`
- **Artifact Detection**: `crypto_wallet_detector.py`, `teamviewer_detector.py`
- **Browser Analysis**: `browser_extension_analyzer.py`,
  `google_drive_analyzer.py`
- **Timeline Analysis**: `system_timeline_analyzer.py`,
  `timeline_correlation.py`
- **Bitcoin Detection**: `bitcoin_finder.py` (note: prone to false positives)

#### Data Sanitization (`/scripts_anonymizers`, `/scripts_github_de-blocker`)

Tools for removing sensitive information:

- Anonymizes personal data in reports
- Removes OAuth tokens and secrets
- Prepares data for safe sharing/publication

## Features

### Browser Extension Analysis

- Detection and classification of browser extensions
- Risk assessment based on permissions and capabilities
- Identification of high-risk extensions (remote access, cryptocurrency)
- Timeline of extension installation and activity

### URL Analysis

- Categorization of URLs by type (suspicious, normal)
- Detection of potential data exfiltration channels
- Identification of cryptocurrency and blockchain activity (_unreliable_)
- Analysis of sensitive document access

### System Timeline Correlation

- Mapping browser activity to system events
- Identification of key suspicious timeframes
- Correlation of document access with system changes

### Specialized Detectors

- TeamViewer activity detection and analysis
- Cryptocurrency wallet artifact identification
- Google Drive document access and classification

## Installation

This project requires Python 3.8+ and Poetry for dependency management.

```bash
# Clone the repository
git clone <repository-url>
cd forensics-processor

# Install dependencies
poetry install
```

## Split Up CSVs

The Python script at project root takes huge CSV files and splits them into
sequentially-numbered CSVs (+ Excel workbooks) of 500k rows apiece until all
content is processed.

`poetry run python process_large_csv.py <filename.csv>`

## Run analysis scripts

```
poetry run python scripts_forensic/browser_extension_analyzer.py --input-file \
  data/extensions.csv --output-dir forensic_analysis/browser_extensions
```

## Usage Examples

### Analyzing Browser Extensions

```bash
poetry run python scripts_forensic/browser_extension_analyzer.py \
  --input-file data/extensions.csv \
  --output-dir forensic_analysis/browser_extensions
```

### Detecting Suspicious URLs

```bash
poetry run python scripts_forensic/suspicious_url_analyzer.py \
  --input-file data/browser_history.csv \
  --output-dir forensic_analysis/suspicious_urls
```

### Analyzing Google Drive Activity

```bash
poetry run python scripts_forensic/google_drive_analyzer.py \
  --input-file data/browser_history.csv \
  --output-dir forensic_analysis/google_drive
```

### Correlating Browser and System Events

```bash
poetry run python scripts_forensic/timeline_correlation.py \
  --system-csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --browser-data-dir forensic_analysis \
  --output-dir forensic_analysis/correlation
```

### Specialized Detection

```bash
# TeamViewer Detection
poetry run python scripts_forensic/teamviewer_detector.py \
  --system-csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --output-dir forensic_analysis/teamviewer

# Cryptocurrency Wallet Detection
poetry run python scripts_forensic/crypto_wallet_detector.py \
  --system-csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --output-dir forensic_analysis/crypto_wallet
```

## Output Reports

All analysis scripts generate detailed reports in both CSV format (for further
analysis) and Markdown format (for human readability). The executive summary
(`forensic_analysis/EXECUTIVE_SUMMARY.md`) provides a comprehensive overview of
all findings.

## Data Handling Policy

- Do not commit raw forensic or PII-heavy data. Use encrypted storage or Git LFS
  with restricted access.
- Large JSON arrays should be stored as compressed NDJSON (`.ndjson.gz`) and
  processed with streaming readers.
- Secrets scanning is enforced with pre-commit hooks (gitleaks, trufflehog) and
  CI checks on every push/PR.
- JSON artifacts (e.g., autofill records) are validated against schemas in
  `schemas/` during CI to ensure consistent format.
- The sample dataset under `500k-sanitized-run_*` is synthetic for demonstration
  only.

## Requirements

- Python 3.8+
- Poetry
- pandas
- jsonschema (for CI validation)
- pre-commit (optional, recommended)

## License

None. I don't plan to leave this posted for long.
