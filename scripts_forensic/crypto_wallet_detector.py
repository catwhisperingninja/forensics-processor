#!/usr/bin/env python3
import os
import re
import pandas as pd
import argparse
from datetime import datetime, timedelta
import glob
from pathlib import Path


class CryptoWalletDetector:
    """Analyzes system timeline data for cryptocurrency wallet artifacts"""

    def __init__(self, system_csv_dir, output_dir):
        self.system_csv_dir = system_csv_dir
        self.output_dir = output_dir

        # General cryptocurrency wallet patterns
        self.wallet_patterns = [
            r'wallet',
            r'cryptocurrency',
            r'crypto',
            r'bitcoin',
            r'ethereum',
            r'blockchain',
            r'ledger',
            r'trezor',
            r'private\s*key',
            r'seed\s*phrase',
            r'mnemonic'
        ]

        # Specific wallet application patterns
        self.wallet_apps = [
            r'metamask',
            r'coinbase',
            r'binance',
            r'exodus',
            r'electrum',
            r'myetherwallet',
            r'trustwallet',
            r'phantom',
            r'keplr',
            r'ledger\s*live',
            r'trezor\s*suite'
        ]

        # File path patterns for cryptocurrency wallets
        self.wallet_file_patterns = [
            r'wallet\.dat',
            r'\.wallet',
            r'keystore',
            r'keys\.json',
            r'metamask',
            r'ledgerlive',
            r'bitcoin',
            r'ethereum',
            r'electrum',
            r'blockchain',
            r'\.eth',
            r'\.btc'
        ]

        self.wallet_events = []

    def find_csv_files(self):
        """Find all CSV files in the specified directory"""
        message_files = glob.glob(os.path.join(self.system_csv_dir, "message*.csv"))
        path_files = glob.glob(os.path.join(self.system_csv_dir, "path*.csv"))
        parser_files = glob.glob(os.path.join(self.system_csv_dir, "parser*.csv"))

        relevant_files = message_files + path_files + parser_files
        print(f"Found {len(relevant_files)} relevant CSV files to analyze")
        return relevant_files

    def search_for_wallet_artifacts(self, csv_files):
        """Search for cryptocurrency wallet artifacts in CSV files"""
        pattern_groups = {
            'general': self.wallet_patterns,
            'wallet_app': self.wallet_apps,
            'wallet_file': self.wallet_file_patterns
        }

        for csv_file in csv_files:
            try:
                filename = Path(csv_file).name
                print(f"Processing {filename}...")

                # For large files, use chunking
                if os.path.getsize(csv_file) > 100 * 1024 * 1024:  # > 100MB
                    chunk_size = 100000  # Process in chunks of 100k rows
                    for chunk in pd.read_csv(csv_file, chunksize=chunk_size):
                        self._process_chunk(chunk, pattern_groups, filename)
                else:
                    df = pd.read_csv(csv_file)
                    self._process_chunk(df, pattern_groups, filename)
            except Exception as e:
                print(f"Error processing {csv_file}: {e}")

        print(f"Identified {len(self.wallet_events)} cryptocurrency wallet artifacts")

    def _process_chunk(self, df, pattern_groups, source_file):
        """Process a chunk of data looking for wallet patterns"""
        # Check for value column which contains the data we want to search
        if 'value' not in df.columns:
            return

        # Convert all values to string to ensure we can search them
        df['value'] = df['value'].astype(str)

        # Search for each pattern group
        for group_name, patterns in pattern_groups.items():
            for pattern in patterns:
                # Use case-insensitive search
                matches = df[df['value'].str.contains(pattern, case=False, regex=True)]

                # Process each match
                for _, row in matches.iterrows():
                    event = {
                        'pattern_type': group_name,
                        'pattern': pattern,
                        'value': row['value'],
                        'source_file': source_file
                    }

                    # Extract timestamp if available
                    if 'timestamp' in row:
                        try:
                            event['timestamp'] = row['timestamp']
                            event['datetime'] = datetime.fromisoformat(str(row['timestamp']).replace('Z', '+00:00'))
                        except:
                            event['timestamp'] = 'Unknown'
                            event['datetime'] = None

                    # Extract other useful fields if available
                    for field in ['data_type', 'parser', 'path', 'source', 'timestamp_desc']:
                        if field in row:
                            event[field] = row[field]

                    self.wallet_events.append(event)

    def categorize_wallet_types(self):
        """Categorize detected wallet artifacts by cryptocurrency type"""
        crypto_categories = {
            'bitcoin': [r'bitcoin', r'btc', r'xbt'],
            'ethereum': [r'ethereum', r'eth', r'erc20'],
            'metamask': [r'metamask'],
            'coinbase': [r'coinbase'],
            'binance': [r'binance'],
            'ledger': [r'ledger'],
            'trezor': [r'trezor'],
            'exodus': [r'exodus'],
            'electrum': [r'electrum'],
            'phantom': [r'phantom', r'solana', r'sol'],
            'other': [r'wallet', r'crypto', r'blockchain', r'private key', r'seed']
        }

        for event in self.wallet_events:
            event_value = event['value'].lower()
            event['crypto_type'] = []

            for crypto_type, patterns in crypto_categories.items():
                for pattern in patterns:
                    if re.search(pattern, event_value, re.IGNORECASE):
                        if crypto_type not in event['crypto_type']:
                            event['crypto_type'].append(crypto_type)

            # If no specific type was matched, categorize as 'other'
            if not event['crypto_type']:
                event['crypto_type'] = ['unspecified']

        # Count different wallet types
        wallet_type_counts = {}
        for event in self.wallet_events:
            for crypto_type in event['crypto_type']:
                if crypto_type not in wallet_type_counts:
                    wallet_type_counts[crypto_type] = 0
                wallet_type_counts[crypto_type] += 1

        print("Wallet types detected:")
        for wallet_type, count in sorted(wallet_type_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {wallet_type}: {count}")

        return wallet_type_counts

    def analyze_wallet_timeline(self):
        """Analyze the timeline of wallet-related events"""
        if not self.wallet_events:
            print("No cryptocurrency wallet events found.")
            return None

        # Sort events by timestamp if available
        events_with_time = [e for e in self.wallet_events if 'datetime' in e and e['datetime'] is not None]
        events_without_time = [e for e in self.wallet_events if 'datetime' not in e or e['datetime'] is None]

        sorted_events = sorted(events_with_time, key=lambda x: x['datetime'])

        # Find the earliest and latest wallet events
        if sorted_events:
            earliest_event = sorted_events[0]
            latest_event = sorted_events[-1]

            print(f"Earliest wallet activity: {earliest_event['timestamp']}")
            print(f"Latest wallet activity: {latest_event['timestamp']}")

            # Group events by day to identify activity patterns
            dates = {}
            for event in sorted_events:
                event_date = event['datetime'].date()
                if event_date not in dates:
                    dates[event_date] = []
                dates[event_date].append(event)

            print(f"Wallet activity detected on {len(dates)} distinct dates")

            # Identify dates with high activity
            high_activity_dates = {d: len(e) for d, e in dates.items() if len(e) > 5}
            if high_activity_dates:
                print(f"Dates with high wallet activity:")
                for date, count in sorted(high_activity_dates.items(), key=lambda x: x[1], reverse=True):
                    print(f"  - {date}: {count} events")

        return {
            'events_with_time': sorted_events,
            'events_without_time': events_without_time,
            'activity_by_date': dates if 'dates' in locals() else {}
        }

    def generate_report(self, wallet_types, timeline_analysis=None):
        """Generate a report of cryptocurrency wallet artifacts"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"crypto_wallet_analysis_{timestamp}.md")
        csv_path = os.path.join(self.output_dir, f"crypto_wallet_events_{timestamp}.csv")

        # Save all events to CSV for further analysis
        if self.wallet_events:
            # Convert to DataFrame, handling datetime objects and crypto_type lists
            events_for_csv = []
            for event in self.wallet_events:
                event_copy = event.copy()
                if 'datetime' in event_copy:
                    event_copy['datetime'] = str(event_copy['datetime'])
                if 'crypto_type' in event_copy:
                    event_copy['crypto_type'] = ','.join(event_copy['crypto_type'])
                events_for_csv.append(event_copy)

            df = pd.DataFrame(events_for_csv)
            df.to_csv(csv_path, index=False)
            print(f"Saved {len(self.wallet_events)} cryptocurrency wallet events to {csv_path}")

        with open(report_path, 'w') as f:
            f.write("# Cryptocurrency Wallet Analysis Report\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            f.write("## Summary\n\n")

            if not self.wallet_events:
                f.write("No cryptocurrency wallet artifacts were found in the system timeline.\n\n")
                return report_path

            f.write(f"- Total cryptocurrency wallet artifacts: {len(self.wallet_events)}\n")

            # Add timeline analysis if available
            if timeline_analysis:
                f.write(f"- Events with timestamp: {len(timeline_analysis['events_with_time'])}\n")
                f.write(f"- Events without timestamp: {len(timeline_analysis['events_without_time'])}\n")

                if timeline_analysis['events_with_time']:
                    earliest = timeline_analysis['events_with_time'][0]
                    latest = timeline_analysis['events_with_time'][-1]

                    f.write(f"- Earliest wallet activity: {earliest['timestamp']}\n")
                    f.write(f"- Latest wallet activity: {latest['timestamp']}\n")
                    f.write(f"- Activity period: {(latest['datetime'] - earliest['datetime']).days} days\n")
                    f.write(f"- Distinct dates with activity: {len(timeline_analysis['activity_by_date'])}\n")

            # Wallet type breakdown
            f.write("\n### Cryptocurrency Types Detected\n\n")
            for wallet_type, count in sorted(wallet_types.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- {wallet_type.title()}: {count}\n")

            # Pattern type breakdown
            pattern_types = {}
            for event in self.wallet_events:
                pattern_type = event['pattern_type']
                if pattern_type not in pattern_types:
                    pattern_types[pattern_type] = 0
                pattern_types[pattern_type] += 1

            f.write("\n### Detection by Pattern Type\n\n")
            for pattern_type, count in pattern_types.items():
                f.write(f"- {pattern_type.replace('_', ' ').title()}: {count}\n")

            # Source file breakdown
            source_files = {}
            for event in self.wallet_events:
                source = event['source_file']
                if source not in source_files:
                    source_files[source] = 0
                source_files[source] += 1

            f.write("\n### Detection by Source File\n\n")
            for source, count in source_files.items():
                f.write(f"- {source}: {count}\n")

            # Timeline analysis
            if timeline_analysis and timeline_analysis['events_with_time']:
                f.write("\n## Activity Timeline\n\n")

                # Group by date for clarity
                f.write("### Activity by Date\n\n")
                f.write("| Date | Event Count |\n")
                f.write("|------|------------|\n")

                for date, events in sorted(timeline_analysis['activity_by_date'].items()):
                    f.write(f"| {date} | {len(events)} |\n")

                # Highlight high-activity periods
                high_activity_dates = {d: len(e) for d, e in timeline_analysis['activity_by_date'].items() if len(e) > 5}
                if high_activity_dates:
                    f.write("\n### High Activity Periods\n\n")
                    f.write("The following dates show unusually high cryptocurrency wallet activity:\n\n")

                    for date, count in sorted(high_activity_dates.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"- **{date}**: {count} events\n")

                # Show key events
                f.write("\n### Key Wallet Events\n\n")

                # Find installation events
                install_events = [e for e in timeline_analysis['events_with_time']
                                if any(term in e['value'].lower() for term in ['install', 'setup', 'created'])]

                if install_events:
                    f.write("#### Installation Events\n\n")
                    for event in sorted(install_events[:5], key=lambda x: x['datetime']):
                        f.write(f"- **{event['timestamp']}**: {event['value'][:100]}...\n")

                    if len(install_events) > 5:
                        f.write(f"  *(and {len(install_events) - 5} more installation events)*\n")
                    f.write("\n")

                # Find private key/seed phrase related events (high-risk)
                key_events = [e for e in timeline_analysis['events_with_time']
                            if any(term in e['value'].lower() for term in ['private key', 'seed', 'mnemonic', 'backup'])]

                if key_events:
                    f.write("#### Private Key/Seed Phrase Events\n\n")
                    f.write("⚠️ **SECURITY CONCERN:** Events potentially related to private keys or seed phrases:\n\n")
                    for event in sorted(key_events[:5], key=lambda x: x['datetime']):
                        f.write(f"- **{event['timestamp']}**: {event['value'][:100]}...\n")

                    if len(key_events) > 5:
                        f.write(f"  *(and {len(key_events) - 5} more key-related events)*\n")
                    f.write("\n")

            # Evidence examples by wallet type
            f.write("\n## Evidence by Cryptocurrency Type\n\n")

            # Get top 5 wallet types by count
            top_wallet_types = sorted(wallet_types.items(), key=lambda x: x[1], reverse=True)[:5]

            for wallet_type, _ in top_wallet_types:
                f.write(f"### {wallet_type.title()} Evidence\n\n")

                # Get events for this wallet type
                type_events = [e for e in self.wallet_events if wallet_type in e.get('crypto_type', [])]

                for event in type_events[:5]:  # Show up to 5 examples per type
                    if 'timestamp' in event and event['timestamp'] != 'Unknown':
                        f.write(f"- **{event['timestamp']}**: ")
                    else:
                        f.write("- ")

                    # Truncate very long values
                    value = event['value']
                    if len(str(value)) > 200:
                        value = str(value)[:197] + '...'

                    f.write(f"{value}\n")

                if len(type_events) > 5:
                    f.write(f"  *(and {len(type_events) - 5} more {wallet_type} evidence items)*\n")

                f.write("\n")

            # Conclusions section
            f.write("## Conclusions\n\n")

            if not self.wallet_events:
                f.write("No evidence of cryptocurrency wallet activity was found in the system timeline data.\n")
            else:
                conclusions = []

                # Basic conclusion about wallet presence
                conclusions.append(f"Cryptocurrency wallet artifacts were detected on the system with {len(self.wallet_events)} related artifacts.")

                # Wallet type conclusions
                if 'bitcoin' in wallet_types and wallet_types['bitcoin'] > 0:
                    conclusions.append(f"Bitcoin wallet activity detected with {wallet_types['bitcoin']} artifacts.")

                if 'ethereum' in wallet_types and wallet_types['ethereum'] > 0:
                    conclusions.append(f"Ethereum wallet activity detected with {wallet_types['ethereum']} artifacts.")

                # Hardware wallet conclusions
                if ('ledger' in wallet_types and wallet_types['ledger'] > 0) or ('trezor' in wallet_types and wallet_types['trezor'] > 0):
                    hw_count = wallet_types.get('ledger', 0) + wallet_types.get('trezor', 0)
                    conclusions.append(f"Hardware wallet activity detected with {hw_count} artifacts (Ledger/Trezor).")

                # Exchange wallet conclusions
                if ('coinbase' in wallet_types and wallet_types['coinbase'] > 0) or ('binance' in wallet_types and wallet_types['binance'] > 0):
                    ex_count = wallet_types.get('coinbase', 0) + wallet_types.get('binance', 0)
                    conclusions.append(f"Cryptocurrency exchange wallet activity detected with {ex_count} artifacts (Coinbase/Binance).")

                # MetaMask specifically (browser extension)
                if 'metamask' in wallet_types and wallet_types['metamask'] > 0:
                    conclusions.append(f"MetaMask wallet activity detected with {wallet_types['metamask']} artifacts.")

                # Timeline-based conclusions
                if timeline_analysis and timeline_analysis['events_with_time']:
                    earliest = timeline_analysis['events_with_time'][0]['datetime']
                    latest = timeline_analysis['events_with_time'][-1]['datetime']

                    # Check if wallet was recently used
                    now = datetime.now()
                    if (now - latest).days < 30:
                        conclusions.append("Cryptocurrency wallets were used recently (within the last 30 days).")

                    # Check for long-term usage
                    if (latest - earliest).days > 90:
                        conclusions.append("Evidence suggests long-term cryptocurrency wallet usage over multiple months.")

                    # Check for frequent usage
                    if len(timeline_analysis['activity_by_date']) > 10:
                        conclusions.append("Cryptocurrency wallets were used frequently, on multiple dates.")

                    # Check for high-activity periods
                    high_activity_dates = {d: len(e) for d, e in timeline_analysis['activity_by_date'].items() if len(e) > 5}
                    if high_activity_dates:
                        conclusions.append(f"Intense cryptocurrency wallet activity was detected on {len(high_activity_dates)} dates.")

                # Private key security concerns
                key_events = [e for e in self.wallet_events if any(term in e['value'].lower() for term in ['private key', 'seed', 'mnemonic', 'backup'])]
                if key_events:
                    conclusions.append(f"⚠️ **SECURITY CONCERN:** {len(key_events)} events potentially related to private keys or seed phrases were detected.")

                # Write all conclusions
                for conclusion in conclusions:
                    f.write(f"- {conclusion}\n")

                # Security recommendations
                f.write("\n### Security Considerations\n\n")
                f.write("1. Cryptocurrency wallet presence itself is not inherently suspicious, but should be assessed in context\n")
                f.write("2. Check if cryptocurrency wallet installations and usage aligns with authorized user activity\n")
                f.write("3. Verify if wallet software was used during unauthorized access periods\n")
                f.write("4. Look for evidence of private keys or seed phrases being exported or backed up\n")
                f.write("5. Correlate wallet activity with external device connections or file transfer activities\n")
                f.write("6. Review for evidence of cryptocurrency transfers during suspicious timeframes\n")

        print(f"Generated cryptocurrency wallet analysis report at {report_path}")
        return report_path

    def analyze(self):
        """Main analysis function"""
        csv_files = self.find_csv_files()
        self.search_for_wallet_artifacts(csv_files)
        wallet_types = self.categorize_wallet_types()
        timeline_analysis = self.analyze_wallet_timeline()
        report_path = self.generate_report(wallet_types, timeline_analysis)
        return report_path


def main():
    parser = argparse.ArgumentParser(description='Detect cryptocurrency wallet artifacts in system timeline data')
    parser.add_argument('--system-csv-dir', required=True, help='Directory containing system timeline CSV files')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run detector
    detector = CryptoWalletDetector(args.system_csv_dir, args.output_dir)
    detector.analyze()
    print("Analysis complete!")


if __name__ == "__main__":
    main()