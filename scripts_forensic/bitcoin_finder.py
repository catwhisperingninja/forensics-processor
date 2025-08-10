#!/usr/bin/env python3
import os
import re
import pandas as pd
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
import glob
from tqdm import tqdm
import csv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BitcoinFinder:
    """Find Bitcoin addresses and transactions with advanced context filtering"""

    def __init__(self, input_dirs, output_dir, date_filter=None):
        """Initialize the BitcoinFinder

        Args:
            input_dirs (list): List of directories containing CSV files to scan
            output_dir (str): Directory to save output files
            date_filter (tuple): Optional (start_date, end_date) tuple for filtering (YYYY-MM-DD format)
        """
        self.input_dirs = input_dirs
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up date filter if provided
        self.date_filter = None
        if date_filter and len(date_filter) == 2:
            try:
                self.date_filter = (
                    datetime.strptime(date_filter[0], '%Y-%m-%d'),
                    datetime.strptime(date_filter[1], '%Y-%m-%d')
                )
                logger.info(f"Using date filter: {self.date_filter[0].date()} to {self.date_filter[1].date()}")
            except ValueError:
                logger.warning("Invalid date format. Expected YYYY-MM-DD. Date filtering disabled.")

        # Bitcoin address patterns
        self.btc_address_patterns = {
            'bitcoin_legacy': r'\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # P2PKH format (Legacy)
            'bitcoin_segwit': r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # P2SH format (SegWit)
            'bitcoin_bech32': r'\bbc1[a-z0-9]{39,59}\b',            # Bech32 format (Native SegWit)
        }

        # Bitcoin transaction patterns
        self.btc_transaction_patterns = [
            # Transaction IDs (32 bytes/64 hex chars)
            r'(?:txid|transaction\sid|tx\sid|transaction)[\s:=]+([a-fA-F0-9]{64})\b',
            # Transaction references
            r'(?:bitcoin|btc)\s+(?:transaction|tx|payment)\s+(?:to|from|of)\s+([a-zA-Z0-9]{25,34})',
            # Bitcoin amount patterns
            r'([\d\.]+)\s*(?:btc|bitcoin|xbt)',
            # Receipt indicators
            r'(?:received|got|earned|deposited)\s+(?:[\d\.]+)?\s*(?:btc|bitcoin|xbt)',
            # Block explorer transaction URLs
            r'(?:blockchain\.com/btc/tx|blockstream\.info/tx|btc\.com/btc/transaction)/([a-fA-F0-9]{64})',
            # Confirmation patterns
            r'(\d+)\s+confirmation',
            # Balance check patterns
            r'(?:balance|available)\s*(?:[\d\.]+)?\s*(?:btc|bitcoin)',
        ]

        # Hash patterns to exclude (avoid false positives)
        self.hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'sha512': r'\b[a-fA-F0-9]{128}\b',
        }

        # Context indicators
        self.context_indicators = {
            'block_explorer': [
                'blockchain.com', 'blockchair.com', 'btc.com',
                'blockstream.info', 'mempool.space', 'explorer.bitcoin.com'
            ],
            'wallet_extension': [
                'wallet', 'metamask', 'exodus', 'electrum',
                'coinbase', 'binance', 'ledger', 'trezor'
            ],
            'transaction_terms': [
                'tx', 'txid', 'transaction', 'received', 'sent', 'payment',
                'transfer', 'withdraw', 'deposit', 'exchange'
            ],
            'exclude_contexts': [
                'BuildingLink', 'Microsoft', 'Windows', 'System32',
                'Program Files', 'AppData', 'Import hash', 'file hash',
                'executable', 'dll', 'sys', 'exe', 'msi', 'cab'
            ]
        }

        # Compile regex patterns
        self.hash_regex = re.compile('|'.join(self.hash_patterns.values()))

        # Results storage
        self.findings = {
            'btc_addresses': [],
            'btc_transactions': []
        }
        self.unique_addresses = set()
        self.unique_transactions = set()

        # Stats
        self.stats = {
            'files_processed': 0,
            'rows_processed': 0,
            'address_matches': 0,
            'transaction_matches': 0,
            'false_positives': 0
        }

    def get_csv_files(self):
        """Get all CSV files from input directories"""
        all_files = []
        for input_dir in self.input_dirs:
            files = glob.glob(os.path.join(input_dir, "*.csv"))
            all_files.extend(files)
        logger.info(f"Found {len(all_files)} CSV files to process")
        return all_files

    def is_in_date_range(self, timestamp_str):
        """Check if a timestamp is within the specified date range"""
        if not self.date_filter or not timestamp_str:
            return True  # No filter or no timestamp means include

        try:
            # Handle various timestamp formats
            if 'T' in timestamp_str:
                # ISO format
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                # Try different formats
                timestamp_formats = [
                    '%Y-%m-%d %H:%M:%S.%f',
                    '%Y-%m-%d %H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%d/%m/%Y %H:%M:%S',
                ]

                for fmt in timestamp_formats:
                    try:
                        timestamp = datetime.strptime(timestamp_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return True  # Couldn't parse timestamp, include by default

            # Check if within range
            return self.date_filter[0] <= timestamp <= self.date_filter[1]

        except Exception as e:
            logger.debug(f"Error parsing timestamp {timestamp_str}: {e}")
            return True  # Include by default on error

    def is_likely_false_positive(self, address, context):
        """Check if a Bitcoin address match is likely a false positive"""
        # Check if it's a hash value
        if self.hash_regex.match(address):
            self.stats['false_positives'] += 1
            return True

        # Check excluded contexts
        for exclude in self.context_indicators['exclude_contexts']:
            if exclude.lower() in context.lower():
                self.stats['false_positives'] += 1
                return True

        # Check for positive indicators
        has_transaction_indicator = False
        for term in self.context_indicators['transaction_terms']:
            if term.lower() in context.lower():
                has_transaction_indicator = True
                break

        has_crypto_context = False
        for category in ['block_explorer', 'wallet_extension']:
            for indicator in self.context_indicators[category]:
                if indicator.lower() in context.lower():
                    has_crypto_context = True
                    break
            if has_crypto_context:
                break

        # If neither transaction indicator nor crypto context, likely false positive
        if not (has_transaction_indicator or has_crypto_context):
            self.stats['false_positives'] += 1
            return True

        return False

    def detect_bitcoin_addresses(self, text, row, source_file):
        """Detect Bitcoin addresses in text"""
        if not text or len(text) < 10:
            return

        # Extract timestamp
        timestamp = row.get('datetime', None)
        if not self.is_in_date_range(timestamp):
            return

        for address_type, pattern in self.btc_address_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                address = match.group(0)
                self.stats['address_matches'] += 1

                # Get context around match
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                # Skip false positives
                if self.is_likely_false_positive(address, context):
                    continue

                # Check for receipt indicators
                is_receipt = False
                receipt_indicators = ['received', 'receiving', 'incoming', 'deposited', 'earned', 'got']
                for indicator in receipt_indicators:
                    if indicator.lower() in context.lower():
                        is_receipt = True
                        break

                # Store finding
                finding = {
                    'address': address,
                    'type': address_type,
                    'context': context,
                    'source_file': source_file,
                    'timestamp': timestamp,
                    'is_receipt': is_receipt
                }

                # Add row data
                for key, value in row.items():
                    if key not in finding:
                        finding[key] = value

                self.findings['btc_addresses'].append(finding)
                self.unique_addresses.add(address)

    def detect_bitcoin_transactions(self, text, row, source_file):
        """Detect Bitcoin transaction indicators"""
        if not text or len(text) < 10:
            return

        # Extract timestamp
        timestamp = row.get('datetime', None)
        if not self.is_in_date_range(timestamp):
            return

        # Context terms that increase confidence
        btc_context_terms = [
            'wallet', 'exchange', 'deposit', 'withdraw', 'transfer', 'address',
            'blockchain', 'ledger', 'satoshi', 'block', 'mempool', 'fee', 'confirm'
        ]

        # Search for transaction patterns
        for pattern in self.btc_transaction_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                self.stats['transaction_matches'] += 1

                # Get matched value and context
                matched_value = match.group(0)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                # Calculate confidence based on context terms
                confidence = 1
                for term in btc_context_terms:
                    if term.lower() in context.lower():
                        confidence += 1

                # Skip if confidence is too low
                if confidence < 2:
                    self.stats['false_positives'] += 1
                    continue

                # Check for transaction direction indicators for "received" evidence
                is_receipt = False
                receipt_indicators = ['received', 'receiving', 'incoming', 'deposited', 'earned', 'got']
                for indicator in receipt_indicators:
                    if indicator.lower() in context.lower():
                        is_receipt = True
                        break

                # Look for Bitcoin addresses in the context
                btc_addresses = []
                for addr_type, addr_pattern in self.btc_address_patterns.items():
                    addr_matches = re.finditer(addr_pattern, context, re.IGNORECASE)
                    for addr_match in addr_matches:
                        btc_addresses.append(addr_match.group(0))

                # Store finding
                finding = {
                    'matched_value': matched_value,
                    'context': context,
                    'confidence': confidence,
                    'is_receipt': is_receipt,
                    'source_file': source_file,
                    'timestamp': timestamp
                }

                # Add addresses if found
                if btc_addresses:
                    finding['associated_addresses'] = btc_addresses

                # Add row data
                for key, value in row.items():
                    if key not in finding:
                        finding[key] = value

                self.findings['btc_transactions'].append(finding)
                self.unique_transactions.add(matched_value)

    def process_csv_file(self, file_path):
        """Process a single CSV file for Bitcoin addresses and transactions"""
        logger.info(f"Processing {file_path}")

        try:
            # Process in chunks to handle large files
            chunks = pd.read_csv(file_path, chunksize=10000, low_memory=False)

            for chunk in chunks:
                # Ensure 'message' column exists
                if 'message' not in chunk.columns:
                    continue

                # Convert to records for easy iteration
                records = chunk.to_dict('records')

                for row in records:
                    self.stats['rows_processed'] += 1
                    message = str(row.get('message', ''))

                    # Skip empty messages
                    if not message or message == 'nan':
                        continue

                    # Apply detectors
                    self.detect_bitcoin_addresses(message, row, file_path)
                    self.detect_bitcoin_transactions(message, row, file_path)

            self.stats['files_processed'] += 1

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")

    def run(self):
        """Run the Bitcoin finder analysis"""
        start_time = datetime.now()
        logger.info(f"Starting Bitcoin address and transaction analysis at {start_time}")

        # Get all CSV files
        csv_files = self.get_csv_files()

        # Process each file
        for file_path in tqdm(csv_files, desc="Processing files"):
            self.process_csv_file(file_path)

        # Generate reports
        self.generate_reports()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Analysis completed in {duration:.2f} seconds")
        logger.info(f"Found {len(self.unique_addresses)} unique Bitcoin addresses")
        logger.info(f"Found {len(self.unique_transactions)} unique Bitcoin transactions")
        logger.info(f"Stats: {self.stats}")

    def generate_reports(self):
        """Generate reports of findings"""
        # Save Bitcoin addresses to CSV
        if self.findings['btc_addresses']:
            address_file = self.output_dir / 'bitcoin_addresses.csv'
            with open(address_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'address', 'type', 'timestamp', 'is_receipt',
                    'source_file', 'context', 'source', 'display_name'
                ])
                writer.writeheader()

                for finding in self.findings['btc_addresses']:
                    # Create a clean row with just the fields we want
                    row = {
                        'address': finding.get('address', ''),
                        'type': finding.get('type', ''),
                        'timestamp': finding.get('timestamp', ''),
                        'is_receipt': finding.get('is_receipt', False),
                        'source_file': finding.get('source_file', ''),
                        'context': finding.get('context', ''),
                        'source': finding.get('source', ''),
                        'display_name': finding.get('display_name', '')
                    }
                    writer.writerow(row)

            logger.info(f"Saved Bitcoin addresses to {address_file}")

        # Save Bitcoin transactions to CSV
        if self.findings['btc_transactions']:
            tx_file = self.output_dir / 'bitcoin_transactions.csv'
            with open(tx_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'matched_value', 'timestamp', 'is_receipt', 'confidence',
                    'source_file', 'context', 'source', 'display_name', 'associated_addresses'
                ])
                writer.writeheader()

                for finding in self.findings['btc_transactions']:
                    # Create a clean row with just the fields we want
                    row = {
                        'matched_value': finding.get('matched_value', ''),
                        'timestamp': finding.get('timestamp', ''),
                        'is_receipt': finding.get('is_receipt', False),
                        'confidence': finding.get('confidence', 0),
                        'source_file': finding.get('source_file', ''),
                        'context': finding.get('context', ''),
                        'source': finding.get('source', ''),
                        'display_name': finding.get('display_name', ''),
                        'associated_addresses': ','.join(finding.get('associated_addresses', []))
                    }
                    writer.writerow(row)

            logger.info(f"Saved Bitcoin transactions to {tx_file}")

        # Generate summary report
        summary_file = self.output_dir / 'bitcoin_analysis_summary.md'
        with open(summary_file, 'w') as f:
            f.write("# Bitcoin Analysis Summary\n\n")
            f.write(f"Analysis performed: {datetime.now()}\n\n")

            f.write("## Summary Statistics\n\n")
            f.write(f"- Files processed: {self.stats['files_processed']}\n")
            f.write(f"- Rows processed: {self.stats['rows_processed']}\n")
            f.write(f"- Unique Bitcoin addresses found: {len(self.unique_addresses)}\n")
            f.write(f"- Unique Bitcoin transactions found: {len(self.unique_transactions)}\n")
            f.write(f"- False positives filtered: {self.stats['false_positives']}\n\n")

            if self.date_filter:
                f.write(f"- Date filter: {self.date_filter[0].date()} to {self.date_filter[1].date()}\n\n")

            # Bitcoin receipt evidence
            receipt_evidence = [f for f in self.findings['btc_addresses'] if f.get('is_receipt', False)]
            receipt_txs = [f for f in self.findings['btc_transactions'] if f.get('is_receipt', False)]

            f.write("## Bitcoin Receipt Evidence\n\n")
            if receipt_evidence or receipt_txs:
                # Show address receipt evidence
                if receipt_evidence:
                    f.write("### Bitcoin Addresses with Receipt Evidence\n\n")
                    for evidence in sorted(receipt_evidence[:10], key=lambda x: x.get('timestamp', '')):
                        f.write(f"- **{evidence.get('timestamp', 'Unknown')}**: ")
                        f.write(f"Address `{evidence.get('address', '')}` with receipt context: ")
                        f.write(f"\"*{evidence.get('context', '')[:100]}...*\"\n")

                    if len(receipt_evidence) > 10:
                        f.write(f"\n*...and {len(receipt_evidence) - 10} more addresses with receipt evidence*\n\n")

                # Show transaction receipt evidence
                if receipt_txs:
                    f.write("### Transaction Indicators with Receipt Evidence\n\n")
                    for tx in sorted(receipt_txs[:10], key=lambda x: x.get('timestamp', '')):
                        f.write(f"- **{tx.get('timestamp', 'Unknown')}**: ")
                        f.write(f"Transaction `{tx.get('matched_value', '')}` with receipt context: ")
                        f.write(f"\"*{tx.get('context', '')[:100]}...*\"\n")

                    if len(receipt_txs) > 10:
                        f.write(f"\n*...and {len(receipt_txs) - 10} more transactions with receipt evidence*\n\n")
            else:
                f.write("No direct evidence of Bitcoin receipt found.\n\n")

            # List all unique Bitcoin addresses
            f.write("## All Unique Bitcoin Addresses\n\n")
            for address in sorted(self.unique_addresses):
                f.write(f"- `{address}`\n")

            logger.info(f"Saved summary report to {summary_file}")

def main():
    parser = argparse.ArgumentParser(description='Find Bitcoin addresses and transactions in CSV data')
    parser.add_argument('--input-dirs', '-i', nargs='+', required=True, help='Directories containing CSV files to analyze')
    parser.add_argument('--output-dir', '-o', required=True, help='Directory to save output files')
    parser.add_argument('--start-date', help='Filter for events after this date (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='Filter for events before this date (YYYY-MM-DD)')

    args = parser.parse_args()

    # Set up date filter if provided
    date_filter = None
    if args.start_date and args.end_date:
        date_filter = (args.start_date, args.end_date)

    # Run analysis
    finder = BitcoinFinder(args.input_dirs, args.output_dir, date_filter)
    finder.run()

if __name__ == "__main__":
    main()