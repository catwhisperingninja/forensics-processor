#!/bin/bash
set -euo pipefail
trap 'echo "Error on or near line ${LINENO}" >&2' ERR

# Create the output directories
mkdir -p forensic_analysis/{browser_extensions,suspicious_urls,google_drive,system_timeline,correlation,teamviewer,crypto_wallet}

echo "Running Browser Forensics and System Timeline Correlation Analysis"
echo "=================================================================="
echo

# Step 1: System Timeline Analysis
echo "Step 1: Analyzing System Timeline Data..."
poetry run python scripts_forensic/system_timeline_analyzer.py \
  --csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --output-dir forensic_analysis/system_timeline
echo "System Timeline Analysis Complete!"
echo

# Step 2: TeamViewer Analysis
echo "Step 2: Analyzing TeamViewer Activity..."
poetry run python scripts_forensic/teamviewer_detector.py \
  --system-csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --output-dir forensic_analysis/teamviewer
echo "TeamViewer Analysis Complete!"
echo

# Step 3: Cryptocurrency Wallet Analysis
echo "Step 3: Analyzing Cryptocurrency Wallet Activity..."
poetry run python scripts_forensic/crypto_wallet_detector.py \
  --system-csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --output-dir forensic_analysis/crypto_wallet
echo "Cryptocurrency Wallet Analysis Complete!"
echo

# Step 4: Timeline Correlation Analysis
echo "Step 4: Correlating Browser Activity with System Timeline..."
poetry run python scripts_forensic/timeline_correlation.py \
  --system-csv-dir 500k-csv-splits/batch_analysis/csv_output/categorical \
  --browser-data-dir forensic_analysis \
  --output-dir forensic_analysis/correlation
echo "Timeline Correlation Analysis Complete!"
echo

echo "All Analyses Complete!"
echo "Results are available in the forensic_analysis/ directory."
echo "Executive Summary: forensic_analysis/EXECUTIVE_SUMMARY.md"