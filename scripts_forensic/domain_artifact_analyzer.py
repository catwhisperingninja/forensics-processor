#!/usr/bin/env python3
import os
import re
import pandas as pd
import argparse
from datetime import datetime
import glob
from pathlib import Path
import json
import hashlib
import logging


class DomainArtifactAnalyzer:
    """Analyzes domain data to detect cryptocurrency addresses, Tor domains, and other suspicious artifacts"""

    def __init__(self, domain_csv_dir, output_dir):
        self.domain_csv_dir = domain_csv_dir
        self.output_dir = output_dir

        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(os.path.join(output_dir, "domain_analysis.log"))
            ]
        )
        self.logger = logging.getLogger("DomainAnalyzer")

        # Define patterns for cryptocurrency addresses
        self.crypto_address_patterns = {
            # Bitcoin addresses
            'bitcoin_legacy': r'\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b',          # P2PKH format (Legacy) starts with 1
            'bitcoin_segwit': r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b',          # P2SH format (SegWit compatible) starts with 3
            'bitcoin_bech32': r'\bbc1[a-z0-9]{39,59}\b',                    # Bech32 format (Native SegWit) starts with bc1

            # Ethereum and compatible networks
            'ethereum': r'\b0x[a-fA-F0-9]{40}\b',                           # Ethereum, Polygon, BNB Chain, Fantom, Avalanche

            # Litecoin addresses
            'litecoin': r'\b[lL][a-km-zA-HJ-NP-Z1-9]{26,33}\b',            # Legacy Litecoin starts with l or L
            'litecoin_segwit': r'\b[mM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b',    # SegWit Litecoin starts with m, M, or 3

            # Dogecoin addresses
            'dogecoin': r'\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b',   # Starts with D, followed by valid character

            # Monero addresses
            'monero': r'\b[48][a-zA-Z0-9]{93}\b',                          # Starts with 4 or 8, 95 chars total

            # Ripple/XRP addresses
            'ripple': r'\br[a-zA-Z0-9]{33}\b',                             # Starts with r

            # Stellar addresses
            'stellar': r'\bG[a-zA-Z0-9]{55}\b',                            # Starts with G

            # Binance Chain addresses
            'binance': r'\bbnb[a-zA-Z0-9]{39}\b'                           # Starts with bnb
        }

        # Hash algorithm patterns
        self.hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',                    # MD5 hash
            'sha1': r'\b[a-fA-F0-9]{40}\b',                   # SHA1 hash
            'sha256': r'\b[a-fA-F0-9]{64}\b',                 # SHA256 hash
            'sha512': r'\b[a-fA-F0-9]{128}\b',                # SHA512 hash
            'ripemd160': r'\b[a-fA-F0-9]{40}\b',              # RIPE MD160 hash
            'import_hash': r'\b[a-fA-F0-9]{32}\b',            # Import hash
            'file_hash': r'\b[a-fA-F0-9]{32,128}\b'           # Generic file hash
        }

        # Context indicators for filtering
        self.crypto_context_indicators = {
            'block_explorer': [
                'blockchain.com', 'blockchair.com', 'etherscan.io',
                'bscscan.com', 'polygonscan.com', 'explorer.bitcoin.com',
                'btc.com', 'live.blockcypher.com', 'blockstream.info',
                'mempool.space', 'blockexplorer.com', 'sochain.com'
            ],
            'wallet_extension': [
                'chrome-extension://', 'firefox-extension://',
                'metamask', 'phantom', 'trustwallet', 'coinbase-wallet',
                'exodus', 'electrum', 'mycrypto', 'mycelium', 'wasabi',
                'bitcoin wallet', 'crypto wallet', 'wallet extension'
            ],
            'wallet_files': [
                '.dat', 'wallet.dat', 'bitcoin.conf', 'bitcoin.conf',
                'keys.dat', 'seed.dat', 'backup.dat'
            ],
            'transaction_indicators': [
                'tx', 'txid', 'transaction', 'btc', 'bitcoin', 'wallet',
                'address', 'send', 'sent', 'receive', 'received',
                'transfer', 'payment', 'confirm', 'confirmation',
                'balance', 'deposit', 'withdrawal', 'exchange'
            ],
            'exclude_contexts': [
                 'Microsoft', 'Windows', 'System32',
                'Program Files', 'AppData', 'Import hash', 'file hash',
                'executable', 'dll', 'sys', 'exe', 'msi', 'cab'
            ]
        }

        # Combined regex for any crypto address
        self.any_crypto_regex = re.compile('|'.join([pattern for pattern in self.crypto_address_patterns.values()]))

        # Combined regex for hash algorithms
        self.any_hash_regex = re.compile('|'.join([pattern for pattern in self.hash_patterns.values()]))

        # Define pattern for Tor onion domains
        self.tor_domain_regex = re.compile(r'\b[a-z2-7]{16,56}\.onion\b')

        # Define patterns for wallet seed phrases
        self.seed_phrase_indicators = [
            r'recovery\s+phrase',
            r'seed\s+phrase',
            r'mnemonic\s+phrase',
            r'backup\s+phrase',
            r'wallet\s+words',
            r'secret\s+recovery\s+phrase'
        ]

        # Categories for analysis findings
        self.artifact_categories = [
            'wallet_address',
            'wallet_file',
            'extension_file',
            'tor_domain',
            'exchange_visit',
            'wallet_configuration',
            'seed_phrase',
            'private_key'
        ]

        # Known cryptocurrency exchanges and services
        self.crypto_services = [
            'binance.com', 'coinbase.com', 'kraken.com', 'gemini.com', 'bitfinex.com',
            'bitstamp.net', 'kucoin.com', 'ftx.com', 'bittrex.com', 'crypto.com',
            'blockchain.com', 'bitcoinira.com', 'metamask.io', 'trezor.io', 'ledger.com',
            'exodus.com', 'trustwallet.com', 'phantom.app', 'myetherwallet.com'
        ]

        # Results storage
        self.findings = {category: [] for category in self.artifact_categories}
        self.crypto_addresses = set()
        self.tor_domains = set()
        self.timeline_events = []
        self.user_accounts = set()

        # Counters
        self.processed_rows = 0
        self.processed_files = 0

    def find_domain_files(self):
        """Find all domain CSV files in the specified directory"""
        domain_files = glob.glob(os.path.join(self.domain_csv_dir, "*.csv"))
        self.logger.info(f"Found {len(domain_files)} domain CSV files to analyze")
        return domain_files

    def process_domain_files(self):
        """Process all domain CSV files to extract artifacts"""
        domain_files = self.find_domain_files()

        for csv_file in domain_files:
            try:
                filename = Path(csv_file).name
                self.logger.info(f"Processing {filename}...")

                # For large files, use chunking
                if os.path.getsize(csv_file) > 100 * 1024 * 1024:  # > 100MB
                    chunk_size = 100000  # Process in chunks of 100k rows
                    for i, chunk in enumerate(pd.read_csv(csv_file, chunksize=chunk_size)):
                        self.logger.info(f"Processing chunk {i+1} of {filename}...")
                        self._process_chunk(chunk, filename)
                else:
                    df = pd.read_csv(csv_file)
                    self._process_chunk(df, filename)

                self.processed_files += 1
            except Exception as e:
                self.logger.error(f"Error processing {csv_file}: {e}")

        self.logger.info(f"Processed {self.processed_rows:,} rows across {self.processed_files} files")
        self.logger.info(f"Found {sum(len(findings) for findings in self.findings.values())} artifacts")

        # Summarize findings by category
        for category, items in self.findings.items():
            self.logger.info(f"  - {category}: {len(items)} items")

        # Log unique addresses and domains
        self.logger.info(f"Discovered {len(self.crypto_addresses)} unique cryptocurrency addresses")
        self.logger.info(f"Discovered {len(self.tor_domains)} unique Tor onion domains")

    def _process_chunk(self, df, source_file):
        """Process a chunk of domain data"""
        if 'message' not in df.columns:
            self.logger.warning(f"Skipping chunk in {source_file} - 'message' column not found")
            return

        # Count rows
        rows_in_chunk = len(df)
        self.processed_rows += rows_in_chunk

        # Make sure message column is string
        df['message'] = df['message'].astype(str)

        # Look for crypto addresses in message column
        for _, row in df.iterrows():
            # Skip if message is too short
            if len(row['message']) < 10:
                continue

            # Categorize and store artifacts
            self.categorize_artifacts(row, source_file)

        self.logger.info(f"Processed {rows_in_chunk:,} rows from {source_file}")

    def extract_timestamp(self, row):
        """Extract timestamp from row data"""
        if 'datetime' in row and row['datetime'] and str(row['datetime']).lower() not in ['nan', 'nat', '0000-00-00t00:00:00.000000+00:00']:
            try:
                # Parse the timestamp
                timestamp_str = str(row['datetime'])
                if timestamp_str.startswith('0000-00-00') or timestamp_str.startswith('1601-01-01'):
                    return None  # Invalid or default timestamp

                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except Exception:
                pass
        return None

    def extract_user_account(self, row):
        """Extract user account from row data"""
        # Look for user account in display_name or message
        for field in ['display_name', 'message']:
            if field in row and isinstance(row[field], str):
                # Look for common Windows user paths
                user_match = re.search(r'\\Users\\([^\\]+)\\', str(row[field]))
                if user_match:
                    self.user_accounts.add(user_match.group(1))
                    return user_match.group(1)

        return None

    def detect_wallet_addresses(self, text, row, source_file):
        """Detect cryptocurrency wallet addresses"""
        # Skip empty text
        if not text or len(text) < 10:
            return

        # Extract user account and timestamp
        user_account = self.extract_user_account(row)
        timestamp = self.extract_timestamp(row)

        # Look for crypto addresses
        for address_type, pattern in self.crypto_address_patterns.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                address = match.group(0)

                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                # Skip if it's likely a false positive
                if self.is_likely_false_positive(address, context):
                    continue

                # For Bitcoin addresses, additional validation
                if address_type.startswith('bitcoin_'):
                    # Skip if it's a hash value
                    if self.any_hash_regex.match(address):
                        continue

                    # Skip if it's in an invalid context
                    if any(exclude.lower() in context.lower() for exclude in self.crypto_context_indicators['exclude_contexts']):
                        continue

                    # Check for positive Bitcoin transaction indicators
                    has_transaction_indicator = False
                    for indicator in self.crypto_context_indicators['transaction_indicators']:
                        if indicator.lower() in context.lower():
                            has_transaction_indicator = True
                            break

                    # If in browser context, check for positive indicators
                    if 'WEBHIST' in str(row.get('source', '')):
                        # If no transaction indicator and not in a crypto-related context, likely false positive
                        is_in_crypto_context = False
                        for category in ['block_explorer', 'wallet_extension']:
                            for indicator in self.crypto_context_indicators[category]:
                                if indicator.lower() in context.lower():
                                    is_in_crypto_context = True
                                    break
                            if is_in_crypto_context:
                                break

                        if not (has_transaction_indicator or is_in_crypto_context):
                            continue

                # Store the address with metadata
                address_data = {
                    'address': address,
                    'type': address_type,
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    'user_account': user_account,
                    'context': context,
                    'source_file': source_file
                }

                # Add to findings
                self.findings['wallet_address'].append(address_data)
                self.crypto_addresses.add(address)

                # Add to timeline
                if timestamp:
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': 'wallet_address',
                        'details': f"Found {address_type} address: {address}",
                        'user_account': user_account,
                        'source_file': source_file
                    })

    def detect_tor_domains(self, text, row, source_file):
        """Search for Tor onion domains in text"""
        matches = self.tor_domain_regex.finditer(text)
        for match in matches:
            domain = match.group(0)

            # Store the domain
            self.tor_domains.add(domain)

            # Create finding
            finding = {
                'domain': domain,
                'context': text[max(0, match.start() - 30):min(len(text), match.end() + 30)],
                'source_file': source_file,
                'timestamp': row.get('datetime', 'Unknown'),
                'user_account': self.extract_user_account(row)
            }

            # Add timestamp-based attributes if available
            timestamp = self.extract_timestamp(row)
            if timestamp:
                finding['datetime'] = timestamp

            # Add to findings and timeline
            self.findings['tor_domain'].append(finding)

            # Add to timeline if timestamp exists
            if timestamp:
                self.timeline_events.append({
                    'timestamp': timestamp,
                    'event_type': 'tor_domain_access',
                    'domain': domain,
                    'source_file': source_file,
                    'user_account': finding['user_account']
                })

    def detect_exchange_visits(self, text, row, source_file):
        """Detect visits to cryptocurrency exchanges"""
        for exchange in self.crypto_services:
            if exchange in text.lower():
                # Create finding
                finding = {
                    'exchange': exchange,
                    'context': text,
                    'source_file': source_file,
                    'timestamp': row.get('datetime', 'Unknown'),
                    'user_account': self.extract_user_account(row)
                }

                # Add timestamp-based attributes if available
                timestamp = self.extract_timestamp(row)
                if timestamp:
                    finding['datetime'] = timestamp

                # Add to findings and timeline
                self.findings['exchange_visit'].append(finding)

                # Add to timeline if timestamp exists
                if timestamp:
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': 'exchange_visit',
                        'exchange': exchange,
                        'source_file': source_file,
                        'user_account': finding['user_account']
                    })

    def detect_wallet_files(self, text, row, source_file):
        """Detect cryptocurrency wallet files"""
        # Check for paths that might indicate wallet files
        wallet_path_indicators = [
            r'\\wallet\.dat',
            r'\.wallet',
            r'\\keystore',
            r'\\keys\.json',
            r'\\metamask',
            r'\\ledgerlive',
            r'\\bitcoin',
            r'\\ethereum',
            r'\\electrum',
            r'\\blockchain',
            r'\.eth\\',
            r'\.btc\\'
        ]

        for indicator in wallet_path_indicators:
            if re.search(indicator, text, re.IGNORECASE):
                # Create finding
                finding = {
                    'indicator': indicator,
                    'path': text,
                    'source_file': source_file,
                    'timestamp': row.get('datetime', 'Unknown'),
                    'user_account': self.extract_user_account(row)
                }

                # Add timestamp-based attributes if available
                timestamp = self.extract_timestamp(row)
                if timestamp:
                    finding['datetime'] = timestamp

                # Add to findings and timeline
                self.findings['wallet_file'].append(finding)

                # Add to timeline if timestamp exists
                if timestamp:
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': 'wallet_file_activity',
                        'path': text,
                        'source_file': source_file,
                        'user_account': finding['user_account']
                    })

    def detect_seed_phrases(self, text, row, source_file):
        """Detect potential cryptocurrency seed phrases"""
        # Look for seed phrase indicators
        for indicator in self.seed_phrase_indicators:
            if re.search(indicator, text, re.IGNORECASE):
                # Create finding
                finding = {
                    'indicator': indicator,
                    'context': text,
                    'source_file': source_file,
                    'timestamp': row.get('datetime', 'Unknown'),
                    'user_account': self.extract_user_account(row)
                }

                # Add timestamp-based attributes if available
                timestamp = self.extract_timestamp(row)
                if timestamp:
                    finding['datetime'] = timestamp

                # Add to findings and timeline
                self.findings['seed_phrase'].append(finding)

                # Add to timeline if timestamp exists
                if timestamp:
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': 'seed_phrase_mention',
                        'indicator': indicator,
                        'source_file': source_file,
                        'user_account': finding['user_account']
                    })

    def detect_private_keys(self, text, row, source_file):
        """Detect potential cryptocurrency private keys"""
        # Patterns for private keys
        private_key_patterns = [
            r'\bL[a-km-zA-HJ-NP-Z1-9]{51}\b',  # Bitcoin WIF private key
            r'\b5[a-km-zA-HJ-NP-Z1-9]{50}\b',  # Bitcoin WIF private key
            r'\bK[a-km-zA-HJ-NP-Z1-9]{51}\b',  # Bitcoin WIF private key (compressed)
            r'\b0x[a-fA-F0-9]{64}\b',          # Ethereum private key
            r'\b[a-fA-F0-9]{64}\b'             # Generic 32-byte (64 hex) private key
        ]

        for pattern in private_key_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                key = match.group(0)

                # Avoid false positives (high entropy is typical for private keys)
                if not self.is_high_entropy(key):
                    continue

                # Create finding
                finding = {
                    'key_pattern': pattern,
                    'context': text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                    'source_file': source_file,
                    'timestamp': row.get('datetime', 'Unknown'),
                    'user_account': self.extract_user_account(row)
                }

                # Add timestamp-based attributes if available
                timestamp = self.extract_timestamp(row)
                if timestamp:
                    finding['datetime'] = timestamp

                # Add to findings and timeline
                self.findings['private_key'].append(finding)

                # Add to timeline if timestamp exists
                if timestamp:
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': 'private_key_found',
                        'source_file': source_file,
                        'user_account': finding['user_account']
                    })

    def is_high_entropy(self, text):
        """Check if text has high entropy (characteristic of keys/random data)"""
        # Simple entropy calculation
        if len(text) < 32:  # Too short to be a key
            return False

        # Count unique characters
        unique_chars = len(set(text))
        # Calculate entropy as percentage of maximum possible entropy
        entropy = unique_chars / len(text)

        return entropy > 0.5  # Arbitrary threshold

    def is_likely_false_positive(self, address, context):
        """Check if an address match is likely a false positive"""
        # Check if it's in a code context
        code_indicators = ['function', 'var ', 'const ', 'return ', 'class ', 'import ']
        for indicator in code_indicators:
            if indicator in context:
                return True

        # Check if it's in a debug/log context
        log_indicators = ['debug', 'log', 'trace', 'error:', 'warning:']
        for indicator in log_indicators:
            if indicator in context.lower():
                return True

        # Check if it's a file path or system identifier
        system_indicators = ['file', 'path', 'directory', 'folder', 'system', 'config', 'settings']
        for indicator in system_indicators:
            if indicator in context.lower() and 'wallet' not in context.lower():
                return True

        # Check if it matches any hash algorithm pattern
        if self.any_hash_regex.match(address):
            return True

        # Check if it's in an excluded context
        for exclude in self.crypto_context_indicators['exclude_contexts']:
            if exclude.lower() in context.lower():
                return True

        # Check specifically for Bitcoin address context
        if address.startswith(('1', '3', 'bc1')):
            # Check for positive transaction indicators that suggest this is a real Bitcoin address
            has_transaction_indicator = False
            for indicator in ['tx', 'txid', 'transaction', 'address', 'bitcoin', 'btc', 'wallet',
                             'send', 'sent', 'receive', 'received', 'payment', 'deposit']:
                if indicator.lower() in context.lower():
                    has_transaction_indicator = True
                    break

            # Not a false positive if we have transaction indicators
            if has_transaction_indicator:
                return False

            # Check for block explorer or wallet context
            has_crypto_context = False
            for category in ['block_explorer', 'wallet_extension']:
                for indicator in self.crypto_context_indicators[category]:
                    if indicator.lower() in context.lower():
                        has_crypto_context = True
                        break
                if has_crypto_context:
                    break

            # If we have a crypto context, it's not a false positive
            if has_crypto_context:
                return False

        # Check if it's in a valid crypto context
        is_valid_context = False
        for category, indicators in self.crypto_context_indicators.items():
            if category != 'exclude_contexts':
                for indicator in indicators:
                    if indicator.lower() in context.lower():
                        is_valid_context = True
                        break
                if is_valid_context:
                    break

        if not is_valid_context:
            return True

        # Get prefix and body for address validation
        prefix = ""
        body = ""

        if address.startswith('1'):  # Bitcoin Legacy
            prefix = address[:1]
        elif address.startswith('3'):  # Bitcoin SegWit
            prefix = address[:1]
        elif address.startswith('bc1'):  # Bitcoin Bech32
            prefix = address[:3]
        elif address.startswith('0x'):  # Ethereum and compatible networks
            prefix = address[:2]
        elif address.startswith('l') or address.startswith('L'):  # Litecoin Legacy
            prefix = address[:1]
        elif address.startswith('m') or address.startswith('M'):  # Litecoin SegWit
            prefix = address[:1]
        elif address.startswith('D'):  # Dogecoin
            prefix = address[:1]
        elif address.startswith('4') or address.startswith('8'):  # Monero
            prefix = address[:1]
        elif address.startswith('r'):  # Ripple/XRP
            prefix = address[:1]
        elif address.startswith('G'):  # Stellar
            prefix = address[:1]
        elif address.startswith('bnb'):  # Binance Chain
            prefix = address[:3]
        else:
            return True  # Unknown prefix, likely false positive

        body = address[len(prefix):]

        # Special case for Bech32 (bc1) addresses - must be all lowercase
        if address.startswith('bc1'):
            return not body.islower()

        # For Monero addresses - must be alphanumeric
        if address.startswith(('4', '8')):
            return not body.isalnum()

        # For other addresses, check if they're consistently upper or lower case
        # and contain only valid characters
        valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
        return not (body.isupper() or body.islower()) or not all(c in valid_chars for c in body)

    def categorize_artifacts(self, row, source_file):
        """Categorize artifacts in a row"""
        message = str(row.get('message', ''))

        # Skip empty messages
        if not message or message == 'nan':
            return

        # Run detection methods
        self.detect_wallet_addresses(message, row, source_file)
        self.detect_tor_domains(message, row, source_file)
        self.detect_exchange_visits(message, row, source_file)
        self.detect_wallet_files(message, row, source_file)
        self.detect_seed_phrases(message, row, source_file)
        self.detect_private_keys(message, row, source_file)
        self.detect_bitcoin_transactions(message, row, source_file)

    def detect_bitcoin_transactions(self, text, row, source_file):
        """Detect Bitcoin transaction indicators"""
        # Bitcoin transaction patterns
        btc_transaction_patterns = [
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

        # Context terms that increase confidence
        btc_context_terms = [
            'wallet', 'exchange', 'deposit', 'withdraw', 'transfer', 'address',
            'blockchain', 'ledger', 'satoshi', 'block', 'mempool', 'fee', 'confirm'
        ]

        # Extract user account and timestamp
        user_account = self.extract_user_account(row)
        timestamp = self.extract_timestamp(row)

        # Search for transaction patterns
        for pattern in btc_transaction_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Get the matched value and context
                matched_value = match.group(0)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                # Calculate confidence based on context terms
                confidence = 1
                for term in btc_context_terms:
                    if term in context.lower():
                        confidence += 1

                # Skip if confidence is too low (avoid false positives)
                if confidence < 2:
                    continue

                # Check for transaction direction indicators for "received" evidence
                is_receipt = False
                receipt_indicators = ['received', 'receiving', 'incoming', 'deposited', 'earned', 'got']
                for indicator in receipt_indicators:
                    if indicator in context.lower():
                        is_receipt = True
                        break

                # Create finding
                finding = {
                    'pattern': pattern,
                    'matched_value': matched_value,
                    'context': context,
                    'is_receipt': is_receipt,
                    'confidence': confidence,
                    'source_file': source_file,
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    'user_account': user_account
                }

                # Look for Bitcoin addresses in the context
                btc_addresses = []
                for addr_type in ['bitcoin_legacy', 'bitcoin_segwit', 'bitcoin_bech32']:
                    addr_pattern = self.crypto_address_patterns[addr_type]
                    addr_matches = re.finditer(addr_pattern, context)
                    for addr_match in addr_matches:
                        btc_addresses.append(addr_match.group(0))

                if btc_addresses:
                    finding['associated_addresses'] = btc_addresses

                # Add to specialized tx findings category (create if not exists)
                if 'bitcoin_transaction' not in self.findings:
                    self.findings['bitcoin_transaction'] = []

                self.findings['bitcoin_transaction'].append(finding)

                # Add to timeline
                if timestamp:
                    tx_type = "Bitcoin receipt" if is_receipt else "Bitcoin transaction"
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': 'bitcoin_transaction',
                        'details': f"{tx_type}: {matched_value}",
                        'user_account': user_account,
                        'source_file': source_file
                    })

    def analyze_timeline(self):
        """Analyze the timeline of events"""
        if not self.timeline_events:
            self.logger.warning("No timeline events to analyze")
            return {}

        # Sort events by timestamp
        sorted_events = sorted(self.timeline_events, key=lambda x: x['timestamp'])

        # Find earliest and latest events
        earliest_event = sorted_events[0]
        latest_event = sorted_events[-1]

        # Group events by date
        events_by_date = {}
        for event in sorted_events:
            date = event['timestamp'].date()
            if date not in events_by_date:
                events_by_date[date] = []
            events_by_date[date].append(event)

        # Identify dates with high activity
        high_activity_dates = {d: len(e) for d, e in events_by_date.items() if len(e) > 5}

        # Log timeline analysis results
        self.logger.info(f"Timeline Analysis:")
        self.logger.info(f"  - Earliest event: {earliest_event['timestamp']}")
        self.logger.info(f"  - Latest event: {latest_event['timestamp']}")
        self.logger.info(f"  - Total events: {len(sorted_events)}")
        self.logger.info(f"  - Events on {len(events_by_date)} distinct dates")

        if high_activity_dates:
            self.logger.info(f"  - High activity dates:")
            for date, count in sorted(high_activity_dates.items(), key=lambda x: x[1], reverse=True)[:5]:
                self.logger.info(f"    - {date}: {count} events")

        return {
            'events': sorted_events,
            'earliest_event': earliest_event,
            'latest_event': latest_event,
            'events_by_date': events_by_date,
            'high_activity_dates': high_activity_dates
        }

    def generate_reports(self):
        """Generate reports for findings"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Analyze timeline
        timeline_analysis = self.analyze_timeline()

        # Generate Markdown report
        report_path = os.path.join(self.output_dir, f"domain_analysis_report_{timestamp}.md")
        self._generate_markdown_report(report_path, timeline_analysis)

        # Generate CSV reports for each category
        for category, items in self.findings.items():
            if items:
                csv_path = os.path.join(self.output_dir, f"domain_{category}_{timestamp}.csv")
                self._generate_csv_report(csv_path, items)

        # Generate full timeline CSV
        if self.timeline_events:
            timeline_path = os.path.join(self.output_dir, f"domain_timeline_{timestamp}.csv")
            self._generate_timeline_csv(timeline_path)

        # Generate JSON files for wallet addresses and Tor domains
        if self.crypto_addresses:
            address_path = os.path.join(self.output_dir, f"cryptocurrency_addresses_{timestamp}.json")
            with open(address_path, 'w') as f:
                json.dump(list(self.crypto_addresses), f, indent=2)
            self.logger.info(f"Saved {len(self.crypto_addresses)} cryptocurrency addresses to {address_path}")

        if self.tor_domains:
            domain_path = os.path.join(self.output_dir, f"tor_domains_{timestamp}.json")
            with open(domain_path, 'w') as f:
                json.dump(list(self.tor_domains), f, indent=2)
            self.logger.info(f"Saved {len(self.tor_domains)} Tor domains to {domain_path}")

    def _generate_markdown_report(self, report_path, timeline_analysis):
        """Generate a Markdown report of findings"""
        with open(report_path, 'w') as f:
            f.write("# Domain Data Analysis Report\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            # Summary section
            f.write("## Summary\n\n")
            f.write(f"- Files Processed: {self.processed_files}\n")
            f.write(f"- Rows Analyzed: {self.processed_rows:,}\n")
            f.write(f"- User Accounts Identified: {len(self.user_accounts)}\n")

            # Artifact counts
            f.write("\n### Artifacts Discovered\n\n")
            for category, items in self.findings.items():
                f.write(f"- {category.replace('_', ' ').title()}: {len(items)}\n")

            # User accounts
            if self.user_accounts:
                f.write("\n### User Accounts\n\n")
                for account in sorted(self.user_accounts):
                    f.write(f"- {account}\n")

            # Timeline overview
            if timeline_analysis:
                f.write("\n## Timeline Overview\n\n")
                f.write(f"- First Activity: {timeline_analysis['earliest_event']['timestamp']}\n")
                f.write(f"- Last Activity: {timeline_analysis['latest_event']['timestamp']}\n")
                f.write(f"- Distinct Dates with Activity: {len(timeline_analysis['events_by_date'])}\n")

                # High activity dates
                if timeline_analysis['high_activity_dates']:
                    f.write("\n### High Activity Dates\n\n")
                    f.write("| Date | Event Count |\n")
                    f.write("|------|------------|\n")

                    for date, count in sorted(timeline_analysis['high_activity_dates'].items(), key=lambda x: x[1], reverse=True):
                        f.write(f"| {date} | {count} |\n")

            # Cryptocurrency addresses
            if self.findings['wallet_address']:
                f.write("\n## Cryptocurrency Addresses\n\n")

                # Group by crypto type
                addresses_by_type = {}
                for item in self.findings['wallet_address']:
                    crypto_type = item['type']
                    if crypto_type not in addresses_by_type:
                        addresses_by_type[crypto_type] = []
                    addresses_by_type[crypto_type].append(item)

                # Output each type
                for crypto_type, addresses in addresses_by_type.items():
                    f.write(f"### {crypto_type.title()} Addresses ({len(addresses)})\n\n")

                    for i, item in enumerate(addresses[:10]):  # Limit to 10 per type
                        f.write(f"{i+1}. `{item['address']}`\n")

                        if 'datetime' in item:
                            f.write(f"   - **Timestamp**: {item['datetime']}\n")

                        if item['user_account']:
                            f.write(f"   - **User**: {item['user_account']}\n")

                        f.write(f"   - **Context**: ```{item['context']}```\n\n")

                    if len(addresses) > 10:
                        f.write(f"*...and {len(addresses) - 10} more {crypto_type} addresses*\n\n")

            # Tor domains
            if self.findings['tor_domain']:
                f.write("\n## Tor Onion Domains\n\n")

                for i, item in enumerate(self.findings['tor_domain'][:20]):  # Limit to 20
                    f.write(f"{i+1}. `{item['domain']}`\n")

                    if 'datetime' in item:
                        f.write(f"   - **Timestamp**: {item['datetime']}\n")

                    if item['user_account']:
                        f.write(f"   - **User**: {item['user_account']}\n")

                    f.write(f"   - **Context**: ```{item['context']}```\n\n")

                if len(self.findings['tor_domain']) > 20:
                    f.write(f"*...and {len(self.findings['tor_domain']) - 20} more Tor domains*\n\n")

            # Exchange visits
            if self.findings['exchange_visit']:
                f.write("\n## Cryptocurrency Exchange Activity\n\n")

                # Group by exchange
                visits_by_exchange = {}
                for item in self.findings['exchange_visit']:
                    exchange = item['exchange']
                    if exchange not in visits_by_exchange:
                        visits_by_exchange[exchange] = []
                    visits_by_exchange[exchange].append(item)

                # Output each exchange
                for exchange, visits in visits_by_exchange.items():
                    f.write(f"### {exchange} ({len(visits)} visits)\n\n")

                    for i, item in enumerate(visits[:5]):  # Limit to 5 per exchange
                        if 'datetime' in item:
                            f.write(f"{i+1}. **{item['datetime']}**\n")
                        else:
                            f.write(f"{i+1}. Visit\n")

                        if item['user_account']:
                            f.write(f"   - **User**: {item['user_account']}\n")

                        # Truncate context if too long
                        context = item['context']
                        if len(context) > 200:
                            context = context[:197] + "..."

                        f.write(f"   - **Context**: {context}\n\n")

                    if len(visits) > 5:
                        f.write(f"*...and {len(visits) - 5} more visits to {exchange}*\n\n")

            # Security concerns section
            f.write("\n## Security Concerns\n\n")

            # Check for private keys or seed phrases (high risk)
            if self.findings['private_key'] or self.findings['seed_phrase']:
                f.write("### ⚠️ HIGH RISK: Private Key or Seed Phrase Exposure\n\n")
                f.write("The following high-risk artifacts suggest potential exposure of cryptocurrency private keys or seed phrases:\n\n")

                # Private keys
                if self.findings['private_key']:
                    f.write("#### Private Keys\n\n")
                    for i, item in enumerate(self.findings['private_key'][:5]):
                        if 'datetime' in item:
                            f.write(f"{i+1}. **{item['datetime']}**\n")
                        else:
                            f.write(f"{i+1}. Discovery\n")

                        if item['user_account']:
                            f.write(f"   - **User**: {item['user_account']}\n")

                        f.write(f"   - **Context**: ```{item['context']}```\n\n")

                    if len(self.findings['private_key']) > 5:
                        f.write(f"*...and {len(self.findings['private_key']) - 5} more private key artifacts*\n\n")

                # Seed phrases
                if self.findings['seed_phrase']:
                    f.write("#### Seed Phrases\n\n")
                    for i, item in enumerate(self.findings['seed_phrase'][:5]):
                        if 'datetime' in item:
                            f.write(f"{i+1}. **{item['datetime']}**\n")
                        else:
                            f.write(f"{i+1}. Discovery\n")

                        if item['user_account']:
                            f.write(f"   - **User**: {item['user_account']}\n")

                        # Truncate context if too long
                        context = item['context']
                        if len(context) > 200:
                            context = context[:197] + "..."

                        f.write(f"   - **Indicator**: {item['indicator']}\n")
                        f.write(f"   - **Context**: ```{context}```\n\n")

                    if len(self.findings['seed_phrase']) > 5:
                        f.write(f"*...and {len(self.findings['seed_phrase']) - 5} more seed phrase artifacts*\n\n")

            # Check for Tor activity
            if self.findings['tor_domain']:
                f.write("### Tor Network Activity\n\n")
                f.write(f"Analysis discovered {len(self.findings['tor_domain'])} instances of Tor onion domain access. ")
                f.write("This activity could indicate attempts to access anonymity networks for legitimate privacy purposes ")
                f.write("or potentially for accessing hidden services.\n\n")

            # Cryptocurrency-related security concerns
            if len(self.crypto_addresses) > 0:
                f.write("### Cryptocurrency Activity\n\n")
                f.write(f"Analysis identified {len(self.crypto_addresses)} unique cryptocurrency addresses across ")
                f.write(f"{len(self.findings['wallet_address'])} references in the system artifacts. ")

                # Add exchange information if available
                if self.findings['exchange_visit']:
                    exchange_count = len(set(item['exchange'] for item in self.findings['exchange_visit']))
                    f.write(f"Additionally, {len(self.findings['exchange_visit'])} visits to {exchange_count} distinct ")
                    f.write("cryptocurrency exchanges were detected.\n\n")
                else:
                    f.write("\n\n")

            # Recommendations section
            f.write("\n## Recommendations\n\n")

            recommendations = []

            if self.findings['private_key'] or self.findings['seed_phrase']:
                recommendations.append(
                    "**URGENT**: Investigate possible cryptocurrency private key and seed phrase exposures. "
                    "These high-risk artifacts suggest potential compromise of cryptocurrency wallets."
                )

            if self.findings['wallet_address']:
                recommendations.append(
                    "Investigate the identified cryptocurrency addresses to determine if they are associated "
                    "with unauthorized transactions or suspicious activities."
                )

            if self.findings['tor_domain']:
                recommendations.append(
                    "Review Tor network activity to determine if access to .onion domains was authorized "
                    "and for legitimate purposes."
                )

            if self.findings['exchange_visit']:
                recommendations.append(
                    "Audit cryptocurrency exchange access to verify authorized usage and to identify "
                    "any suspicious transactions or account activities."
                )

            if timeline_analysis and timeline_analysis['high_activity_dates']:
                recommendations.append(
                    "Focus investigation on high-activity dates identified in the timeline analysis, "
                    "as these may represent periods of concentrated suspicious activity."
                )

            # Add recommendations to report
            for i, recommendation in enumerate(recommendations):
                f.write(f"{i+1}. {recommendation}\n\n")

            f.write("\n*Complete data available in accompanying CSV files*\n")

        self.logger.info(f"Generated Markdown report at {report_path}")
        return report_path

    def _generate_csv_report(self, csv_path, items):
        """Generate a CSV report for a category of findings"""
        # Convert to DataFrame
        df = pd.DataFrame(items)

        # Handle datetime objects
        if 'datetime' in df.columns:
            df['datetime'] = df['datetime'].astype(str)

        # Save to CSV
        df.to_csv(csv_path, index=False)
        self.logger.info(f"Generated CSV report at {csv_path}")

    def _generate_timeline_csv(self, timeline_path):
        """Generate a CSV timeline of events"""
        # Convert to DataFrame
        df = pd.DataFrame(self.timeline_events)

        # Convert datetime objects to strings
        df['timestamp'] = df['timestamp'].astype(str)

        # Sort by timestamp
        df = df.sort_values('timestamp')

        # Save to CSV
        df.to_csv(timeline_path, index=False)
        self.logger.info(f"Generated timeline CSV at {timeline_path}")

    def analyze(self):
        """Run the complete analysis process"""
        self.logger.info("Starting domain artifact analysis...")

        self.process_domain_files()
        self.generate_reports()

        self.logger.info("Domain artifact analysis complete!")


def main():
    parser = argparse.ArgumentParser(description='Analyze domain artifacts for suspicious activity')
    parser.add_argument('--domain-csv-dir', required=True, help='Directory containing domain CSV files')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run analyzer
    analyzer = DomainArtifactAnalyzer(args.domain_csv_dir, args.output_dir)
    analyzer.analyze()


if __name__ == "__main__":
    main()