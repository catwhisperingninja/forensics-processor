#!/bin/bash
set -euo pipefail

# Resolve script directory for robust relative paths
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set up directory paths
SESSIONS_DIR="${DIR}/sessions/split"
DOMAINS_DIR="${DIR}/domains/500k-splits-domains"
SYSTEM_DIR="${DIR}/../500k-csv-splits/batch_analysis/csv_output"
OUTPUT_DIR="${DIR}/bitcoin_findings"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "Starting Bitcoin address and transaction search..."

# First run a quick grep search for basic identification
echo "Running quick grep search for Bitcoin addresses..."

grep -E "(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}" \
  --include="*.csv" -r "$SESSIONS_DIR" "$DOMAINS_DIR" "$SYSTEM_DIR" \
  > "$OUTPUT_DIR/grep_bitcoin_addresses.txt"

echo "Running quick grep search for Bitcoin transactions..."

grep -E "txid|transaction id|tx id|bitcoin.*transaction|btc.*transaction|received.*btc" \
  --include="*.csv" -r "$SESSIONS_DIR" "$DOMAINS_DIR" "$SYSTEM_DIR" \
  > "$OUTPUT_DIR/grep_bitcoin_transactions.txt"

echo "Running quick grep search for .onion domains..."

grep -E "[a-z2-7]{16,56}\.onion" \
  --include="*.csv" -r "$SESSIONS_DIR" "$DOMAINS_DIR" "$SYSTEM_DIR" \
  > "$OUTPUT_DIR/grep_onion_domains.txt"

# Run the full Bitcoin finder with context analysis
echo "Running in-depth Bitcoin address and transaction analysis..."

"${PYTHON:-python3}" "${DIR}/bitcoin_finder.py" \
  --input-dirs "$SESSIONS_DIR" "$DOMAINS_DIR" "$SYSTEM_DIR" \
  --output-dir "$OUTPUT_DIR" \
  --start-date "2024-04-01" \
  --end-date "2024-08-31"

echo "Analysis complete. Results saved to $OUTPUT_DIR/"
echo "Summary report: $OUTPUT_DIR/bitcoin_analysis_summary.md"