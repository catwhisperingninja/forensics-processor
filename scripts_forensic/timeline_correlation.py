#!/usr/bin/env python3
import os
import re
import pandas as pd
import argparse
from datetime import datetime, timedelta
import glob
import json
from pathlib import Path


class TimelineCorrelationAnalyzer:
    """Analyzes system timeline data and correlates with browser activities"""

    def __init__(self, system_csv_dir, browser_data_dir, output_dir):
        self.system_csv_dir = system_csv_dir
        self.browser_data_dir = browser_data_dir
        self.output_dir = output_dir

        # Store key timeframes from browser analysis
        self.key_timeframes = []

        # Store suspicious activity patterns
        self.suspicious_patterns = {
            'teamviewer': [
                r'teamviewer', r'team viewer', r'remote', r'remote desktop',
                r'remote access', r'remote control'
            ],
            'cryptocurrency': [
                r'wallet', r'bitcoin', r'ethereum', r'crypto', r'blockchain',
                r'metamask', r'coinbase', r'binance', r'ledger', r'trezor'
            ],
            'google_drive': [
                r'google drive', r'gdrive', r'drive\.google', r'backup and sync'
            ],
            'external_storage': [
                r'usb', r'removable', r'external', r'flash drive', r'thumb drive',
                r'sd card', r'memory stick'
            ],
            'system_access': [
                r'powershell', r'cmd\.exe', r'command', r'terminal', r'admin',
                r'administrator', r'privilege', r'elevation'
            ]
        }

        # Results storage
        self.correlation_results = {}
        self.suspicious_events = []

    def load_browser_key_timeframes(self):
        """Load key timeframes identified from browser analysis"""
        # Look for extension installation timeframes
        extension_files = glob.glob(os.path.join(self.browser_data_dir, "**", "*extension*.csv"), recursive=True)

        if extension_files:
            print(f"Found {len(extension_files)} extension files for key timeframe extraction")
            for ext_file in extension_files:
                try:
                    df = pd.read_csv(ext_file)
                    # Look for installation timestamps
                    if 'installation_time' in df.columns:
                        for _, row in df.iterrows():
                            # Create a timeframe window around the installation time
                            try:
                                install_time = datetime.fromisoformat(row['installation_time'].replace('Z', '+00:00'))

                                # Create a 24-hour window around the installation
                                timeframe = {
                                    'name': f"Extension Installation: {row.get('name', 'Unknown')}",
                                    'start_time': install_time - timedelta(hours=12),
                                    'end_time': install_time + timedelta(hours=12),
                                    'type': 'extension_install',
                                    'description': f"Installation of {row.get('name', 'Unknown')} extension"
                                }
                                self.key_timeframes.append(timeframe)
                                print(f"Added key timeframe for extension {row.get('name', 'Unknown')}")
                            except Exception as e:
                                print(f"Error parsing installation time: {e}")
                except Exception as e:
                    print(f"Error loading extension file {ext_file}: {e}")

        # Look for suspicious URL visit timeframes
        url_files = glob.glob(os.path.join(self.browser_data_dir, "**", "*url*.csv"), recursive=True)

        if url_files:
            print(f"Found {len(url_files)} URL files for key timeframe extraction")
            for url_file in url_files:
                try:
                    df = pd.read_csv(url_file)
                    # Look for timestamps and suspicious URL patterns
                    if 'timestamp' in df.columns and 'url' in df.columns:
                        # Filter for cryptocurrency or teamviewer related URLs
                        df['is_crypto'] = df['url'].astype(str).apply(
                            lambda u: any(re.search(p, u, re.IGNORECASE) for p in self.suspicious_patterns['cryptocurrency'])
                        )
                        df['is_teamviewer'] = df['url'].astype(str).apply(
                            lambda u: any(re.search(p, u, re.IGNORECASE) for p in self.suspicious_patterns['teamviewer'])
                        )

                        # Group by day and suspicious type to create timeframes
                        df['date'] = pd.to_datetime(df['timestamp']).dt.date

                        # Process crypto visits
                        crypto_days = df[df['is_crypto']]['date'].unique()
                        for day in crypto_days:
                            day_start = datetime.combine(day, datetime.min.time())
                            timeframe = {
                                'name': f"Cryptocurrency URL Visits: {day}",
                                'start_time': day_start,
                                'end_time': day_start + timedelta(hours=24),
                                'type': 'crypto_url_visit',
                                'description': f"Multiple cryptocurrency-related URL visits on {day}"
                            }
                            self.key_timeframes.append(timeframe)

                        # Process teamviewer visits
                        teamviewer_days = df[df['is_teamviewer']]['date'].unique()
                        for day in teamviewer_days:
                            day_start = datetime.combine(day, datetime.min.time())
                            timeframe = {
                                'name': f"TeamViewer URL Visits: {day}",
                                'start_time': day_start,
                                'end_time': day_start + timedelta(hours=24),
                                'type': 'teamviewer_url_visit',
                                'description': f"TeamViewer-related URL visits on {day}"
                            }
                            self.key_timeframes.append(timeframe)

                except Exception as e:
                    print(f"Error loading URL file {url_file}: {e}")

        # Look for Google Drive access timeframes
        drive_files = glob.glob(os.path.join(self.browser_data_dir, "**", "*drive*.csv"), recursive=True)

        if drive_files:
            print(f"Found {len(drive_files)} Google Drive files for key timeframe extraction")
            for drive_file in drive_files:
                try:
                    df = pd.read_csv(drive_file)
                    # Look for timestamps of Google Drive activities
                    if 'timestamp' in df.columns:
                        # Group by day to create timeframes
                        df['date'] = pd.to_datetime(df['timestamp']).dt.date
                        drive_days = df['date'].unique()

                        for day in drive_days:
                            day_start = datetime.combine(day, datetime.min.time())
                            timeframe = {
                                'name': f"Google Drive Activity: {day}",
                                'start_time': day_start,
                                'end_time': day_start + timedelta(hours=24),
                                'type': 'google_drive_activity',
                                'description': f"Google Drive file access on {day}"
                            }
                            self.key_timeframes.append(timeframe)

                except Exception as e:
                    print(f"Error loading Google Drive file {drive_file}: {e}")

        print(f"Identified {len(self.key_timeframes)} key timeframes from browser data")
        return len(self.key_timeframes) > 0

    def extract_datetime(self, row):
        """Extract datetime from system timeline row"""
        # If we have a timestamp field, use that
        if 'timestamp' in row:
            try:
                return datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
            except:
                pass

        # Otherwise try to parse from the value field for common datetime formats
        if 'value' in row:
            datetime_patterns = [
                r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+)',  # ISO format
                r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',      # Common format
                r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'       # MM/DD/YYYY format
            ]

            for pattern in datetime_patterns:
                match = re.search(pattern, str(row['value']))
                if match:
                    try:
                        return datetime.fromisoformat(match.group(1).replace(' ', 'T'))
                    except:
                        pass

        return None

    def is_in_timeframe(self, event_time, timeframes):
        """Check if event time falls within any key timeframes"""
        if event_time is None:
            return False

        for timeframe in timeframes:
            if timeframe['start_time'] <= event_time <= timeframe['end_time']:
                return timeframe

        return False

    def analyze_system_events(self):
        """Analyze system timeline events during key timeframes"""
        # First check if we have any key timeframes
        if not self.key_timeframes:
            print("No key timeframes identified. Run load_browser_key_timeframes first.")
            return False

        # Get a list of all message/data CSV files
        message_files = glob.glob(os.path.join(self.system_csv_dir, "message*.csv"), recursive=True)

        print(f"Found {len(message_files)} message files to analyze")

        # For each file, look for suspicious events during key timeframes
        for msg_file in message_files:
            try:
                print(f"Processing {Path(msg_file).name}...")

                # For large files, use chunking
                if os.path.getsize(msg_file) > 100 * 1024 * 1024:  # > 100MB
                    chunk_size = 100000  # Process in chunks of 100k rows
                    for chunk in pd.read_csv(msg_file, chunksize=chunk_size):
                        self._process_events_chunk(chunk)
                else:
                    df = pd.read_csv(msg_file)
                    self._process_events_chunk(df)

            except Exception as e:
                print(f"Error processing {msg_file}: {e}")

        print(f"Identified {len(self.suspicious_events)} suspicious system events during key timeframes")
        return True

    def _process_events_chunk(self, df):
        """Process a chunk of events data"""
        # Check for suspicious patterns in the value column
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                # Filter for matching events
                matches = df[df['value'].astype(str).str.contains(pattern, case=False, regex=True)]

                # For each match, check if it falls within a key timeframe
                for _, row in matches.iterrows():
                    event_datetime = self.extract_datetime(row)
                    timeframe = self.is_in_timeframe(event_datetime, self.key_timeframes)

                    if timeframe:
                        event = {
                            'timestamp': str(event_datetime) if event_datetime else "Unknown",
                            'value': row['value'],
                            'category': category,
                            'pattern': pattern,
                            'timeframe': timeframe['name'],
                            'timeframe_type': timeframe['type']
                        }

                        # Add count information if available
                        if 'count' in row:
                            event['count'] = row['count']

                        self.suspicious_events.append(event)

    def generate_correlation_report(self):
        """Generate a report of correlated system and browser events"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"correlation_report_{timestamp}.md")
        csv_path = os.path.join(self.output_dir, f"correlation_data_{timestamp}.csv")

        # Save to CSV for further analysis
        if self.suspicious_events:
            df = pd.DataFrame(self.suspicious_events)
            df.to_csv(csv_path, index=False)
            print(f"Saved correlation data to {csv_path}")

        # Group events by timeframe and category
        events_by_timeframe = {}
        for event in self.suspicious_events:
            timeframe = event['timeframe']
            if timeframe not in events_by_timeframe:
                events_by_timeframe[timeframe] = {'events': []}
            events_by_timeframe[timeframe]['events'].append(event)

        with open(report_path, 'w') as f:
            f.write("# Browser and System Timeline Correlation Report\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            # Summary statistics
            f.write("## Summary\n\n")
            f.write(f"- Total Suspicious System Events: {len(self.suspicious_events)}\n")
            f.write(f"- Key Timeframes Analyzed: {len(self.key_timeframes)}\n")
            f.write(f"- Timeframes with Correlated Events: {len(events_by_timeframe)}\n\n")

            # Category breakdown
            categories = {}
            for event in self.suspicious_events:
                cat = event['category']
                if cat not in categories:
                    categories[cat] = 0
                categories[cat] += 1

            f.write("### Events by Category\n\n")
            for cat, count in categories.items():
                f.write(f"- {cat.replace('_', ' ').title()}: {count}\n")
            f.write("\n")

            # Timeframe breakdown
            f.write("## Correlated Events by Timeframe\n\n")

            for timeframe, data in events_by_timeframe.items():
                f.write(f"### {timeframe}\n\n")

                # Group by category within timeframe
                events_by_category = {}
                for event in data['events']:
                    cat = event['category']
                    if cat not in events_by_category:
                        events_by_category[cat] = []
                    events_by_category[cat].append(event)

                # Output by category
                for cat, events in events_by_category.items():
                    f.write(f"#### {cat.replace('_', ' ').title()} ({len(events)} events)\n\n")

                    for event in sorted(events, key=lambda x: x.get('timestamp', '0')):
                        timestamp = event.get('timestamp', 'Unknown Time')
                        value = event.get('value', 'No description')

                        # Truncate very long values
                        if len(str(value)) > 200:
                            value = str(value)[:197] + '...'

                        f.write(f"- **{timestamp}**: {value}\n")

                    f.write("\n")

            # Suspicious pattern analysis
            f.write("## Suspicious Pattern Analysis\n\n")

            # TeamViewer Analysis
            teamviewer_events = [e for e in self.suspicious_events if e['category'] == 'teamviewer']
            if teamviewer_events:
                f.write("### TeamViewer Activity\n\n")
                f.write(f"Detected {len(teamviewer_events)} system events related to TeamViewer during suspicious timeframes.\n\n")

                # Organize by timestamp
                for event in sorted(teamviewer_events[:10], key=lambda x: x.get('timestamp', '0')):
                    timestamp = event.get('timestamp', 'Unknown Time')
                    value = event.get('value', 'No description')
                    timeframe = event.get('timeframe', 'Unknown Timeframe')

                    # Truncate very long values
                    if len(str(value)) > 100:
                        value = str(value)[:97] + '...'

                    f.write(f"- **{timestamp}** ({timeframe}): {value}\n")

                if len(teamviewer_events) > 10:
                    f.write(f"\n*...and {len(teamviewer_events) - 10} more TeamViewer-related events*\n")

                f.write("\n")

            # Cryptocurrency Analysis
            crypto_events = [e for e in self.suspicious_events if e['category'] == 'cryptocurrency']
            if crypto_events:
                f.write("### Cryptocurrency Wallet Activity\n\n")
                f.write(f"Detected {len(crypto_events)} system events related to cryptocurrency wallets during suspicious timeframes.\n\n")

                # Organize by timestamp
                for event in sorted(crypto_events[:10], key=lambda x: x.get('timestamp', '0')):
                    timestamp = event.get('timestamp', 'Unknown Time')
                    value = event.get('value', 'No description')
                    timeframe = event.get('timeframe', 'Unknown Timeframe')

                    # Truncate very long values
                    if len(str(value)) > 100:
                        value = str(value)[:97] + '...'

                    f.write(f"- **{timestamp}** ({timeframe}): {value}\n")

                if len(crypto_events) > 10:
                    f.write(f"\n*...and {len(crypto_events) - 10} more cryptocurrency-related events*\n")

                f.write("\n")

            # External Storage Analysis
            storage_events = [e for e in self.suspicious_events if e['category'] == 'external_storage']
            if storage_events:
                f.write("### External Storage Activity\n\n")
                f.write(f"Detected {len(storage_events)} system events related to external storage during suspicious timeframes.\n\n")

                # Organize by timestamp
                for event in sorted(storage_events[:10], key=lambda x: x.get('timestamp', '0')):
                    timestamp = event.get('timestamp', 'Unknown Time')
                    value = event.get('value', 'No description')
                    timeframe = event.get('timeframe', 'Unknown Timeframe')

                    # Truncate very long values
                    if len(str(value)) > 100:
                        value = str(value)[:97] + '...'

                    f.write(f"- **{timestamp}** ({timeframe}): {value}\n")

                if len(storage_events) > 10:
                    f.write(f"\n*...and {len(storage_events) - 10} more external storage events*\n")

                f.write("\n")

            # Conclusions and recommendations
            f.write("## Conclusions\n\n")

            conclusions = []

            if teamviewer_events:
                conclusions.append("- TeamViewer remote access activity detected during suspicious timeframes")

            if crypto_events:
                conclusions.append("- Cryptocurrency wallet activity found during periods of suspicious browser behavior")

            if storage_events:
                conclusions.append("- External storage devices connected during key timeframes")

            if any(e['category'] == 'google_drive' for e in self.suspicious_events):
                conclusions.append("- Google Drive activity detected in system events during suspicious periods")

            if any(e['category'] == 'system_access' for e in self.suspicious_events):
                conclusions.append("- Elevated system access detected during suspicious time windows")

            if not conclusions:
                f.write("No clear patterns of suspicious activity were identified in system events during key timeframes.\n")
            else:
                for conclusion in conclusions:
                    f.write(f"{conclusion}\n")

            f.write("\n")

        print(f"Generated correlation report at {report_path}")
        return report_path

    def run_correlation_analysis(self):
        """Run the full correlation analysis process"""
        print("Loading browser key timeframes...")
        self.load_browser_key_timeframes()

        print("Analyzing system events...")
        self.analyze_system_events()

        print("Generating correlation report...")
        report_path = self.generate_correlation_report()

        return report_path


def main():
    parser = argparse.ArgumentParser(description='Correlate system timeline with browser activities')
    parser.add_argument('--system-csv-dir', required=True, help='Directory containing system timeline CSV files')
    parser.add_argument('--browser-data-dir', required=True, help='Directory containing browser analysis data')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run analyzer
    analyzer = TimelineCorrelationAnalyzer(args.system_csv_dir, args.browser_data_dir, args.output_dir)
    analyzer.run_correlation_analysis()
    print("Analysis complete!")


if __name__ == "__main__":
    main()