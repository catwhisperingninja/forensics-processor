#!/usr/bin/env python3
import os
import re
import pandas as pd
import argparse
from datetime import datetime, timedelta
import glob
from pathlib import Path


class TeamViewerDetector:
    """Analyzes system timeline data specifically for TeamViewer artifacts"""

    def __init__(self, system_csv_dir, output_dir):
        self.system_csv_dir = system_csv_dir
        self.output_dir = output_dir

        # Set of TeamViewer-specific patterns
        self.teamviewer_patterns = [
            r'teamviewer',
            r'team viewer',
            r'remote access',
            r'remote control',
            r'remote desktop',
            r'TVHelper',
            r'TeamViewer_Service',
            r'teamviewer_\d+.exe',
            r'teamviewergui',
            r'teamviewer_desktop',
            r'RemoteControl',
            r'QuickSupport'
        ]

        # TeamViewer registry key patterns
        self.registry_patterns = [
            r'HKEY_LOCAL_MACHINE\\SOFTWARE\\TeamViewer',
            r'HKEY_CURRENT_USER\\SOFTWARE\\TeamViewer',
            r'TeamViewer\d+',
        ]

        # TeamViewer file path patterns
        self.file_path_patterns = [
            r'TeamViewer',
            r'Program Files.*TeamViewer',
            r'AppData.*TeamViewer',
            r'TeamViewer_Setup',
            r'TeamViewer\d+_Logfile',
            r'Connections_incoming.txt',
            r'TeamViewer\d+_Logfile'
        ]

        self.teamviewer_events = []

    def find_csv_files(self):
        """Find all CSV files in the specified directory"""
        message_files = glob.glob(os.path.join(self.system_csv_dir, "message*.csv"))
        path_files = glob.glob(os.path.join(self.system_csv_dir, "path*.csv"))
        parser_files = glob.glob(os.path.join(self.system_csv_dir, "parser*.csv"))

        relevant_files = message_files + path_files + parser_files
        print(f"Found {len(relevant_files)} relevant CSV files to analyze")
        return relevant_files

    def search_for_teamviewer(self, csv_files):
        """Search for TeamViewer-related events in CSV files"""
        pattern_groups = {
            'general': self.teamviewer_patterns,
            'registry': self.registry_patterns,
            'file_path': self.file_path_patterns
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

        print(f"Identified {len(self.teamviewer_events)} TeamViewer-related events")

    def _process_chunk(self, df, pattern_groups, source_file):
        """Process a chunk of data looking for TeamViewer patterns"""
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

                    self.teamviewer_events.append(event)

    def analyze_teamviewer_timeline(self):
        """Analyze the timeline of TeamViewer events"""
        if not self.teamviewer_events:
            print("No TeamViewer events found.")
            return None

        # Sort events by timestamp if available
        events_with_time = [e for e in self.teamviewer_events if 'datetime' in e and e['datetime'] is not None]
        events_without_time = [e for e in self.teamviewer_events if 'datetime' not in e or e['datetime'] is None]

        sorted_events = sorted(events_with_time, key=lambda x: x['datetime'])

        # Find the earliest and latest TeamViewer events
        if sorted_events:
            earliest_event = sorted_events[0]
            latest_event = sorted_events[-1]

            print(f"Earliest TeamViewer activity: {earliest_event['timestamp']}")
            print(f"Latest TeamViewer activity: {latest_event['timestamp']}")

            # Group events by day to identify activity patterns
            dates = {}
            for event in sorted_events:
                event_date = event['datetime'].date()
                if event_date not in dates:
                    dates[event_date] = []
                dates[event_date].append(event)

            print(f"TeamViewer activity detected on {len(dates)} distinct dates")

            # Identify dates with high activity
            high_activity_dates = {d: len(e) for d, e in dates.items() if len(e) > 5}
            if high_activity_dates:
                print(f"Dates with high TeamViewer activity:")
                for date, count in sorted(high_activity_dates.items(), key=lambda x: x[1], reverse=True):
                    print(f"  - {date}: {count} events")

        return {
            'events_with_time': sorted_events,
            'events_without_time': events_without_time,
            'activity_by_date': dates if 'dates' in locals() else {}
        }

    def generate_report(self, timeline_analysis=None):
        """Generate a report of TeamViewer-related events"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"teamviewer_analysis_{timestamp}.md")
        csv_path = os.path.join(self.output_dir, f"teamviewer_events_{timestamp}.csv")

        # Save all events to CSV for further analysis
        if self.teamviewer_events:
            # Convert to DataFrame, handling datetime objects
            events_for_csv = []
            for event in self.teamviewer_events:
                event_copy = event.copy()
                if 'datetime' in event_copy:
                    event_copy['datetime'] = str(event_copy['datetime'])
                events_for_csv.append(event_copy)

            df = pd.DataFrame(events_for_csv)
            df.to_csv(csv_path, index=False)
            print(f"Saved {len(self.teamviewer_events)} TeamViewer events to {csv_path}")

        with open(report_path, 'w') as f:
            f.write("# TeamViewer Activity Analysis Report\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            f.write("## Summary\n\n")

            if not self.teamviewer_events:
                f.write("No TeamViewer-related events were found in the system timeline.\n\n")
                return report_path

            f.write(f"- Total TeamViewer-related events: {len(self.teamviewer_events)}\n")

            # Add timeline analysis if available
            if timeline_analysis:
                f.write(f"- Events with timestamp: {len(timeline_analysis['events_with_time'])}\n")
                f.write(f"- Events without timestamp: {len(timeline_analysis['events_without_time'])}\n")

                if timeline_analysis['events_with_time']:
                    earliest = timeline_analysis['events_with_time'][0]
                    latest = timeline_analysis['events_with_time'][-1]

                    f.write(f"- Earliest TeamViewer activity: {earliest['timestamp']}\n")
                    f.write(f"- Latest TeamViewer activity: {latest['timestamp']}\n")
                    f.write(f"- Activity period: {(latest['datetime'] - earliest['datetime']).days} days\n")
                    f.write(f"- Distinct dates with activity: {len(timeline_analysis['activity_by_date'])}\n")

            # Pattern type breakdown
            pattern_types = {}
            for event in self.teamviewer_events:
                pattern_type = event['pattern_type']
                if pattern_type not in pattern_types:
                    pattern_types[pattern_type] = 0
                pattern_types[pattern_type] += 1

            f.write("\n### Detection by Pattern Type\n\n")
            for pattern_type, count in pattern_types.items():
                f.write(f"- {pattern_type.title()}: {count}\n")

            # Source file breakdown
            source_files = {}
            for event in self.teamviewer_events:
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
                    f.write("The following dates show unusually high TeamViewer activity:\n\n")

                    for date, count in sorted(high_activity_dates.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"- **{date}**: {count} events\n")

                # Show key events
                f.write("\n### Key TeamViewer Events\n\n")

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

                # Find connection events
                connection_events = [e for e in timeline_analysis['events_with_time']
                                    if any(term in e['value'].lower() for term in ['connect', 'session', 'remote'])]

                if connection_events:
                    f.write("#### Connection Events\n\n")
                    for event in sorted(connection_events[:10], key=lambda x: x['datetime']):
                        f.write(f"- **{event['timestamp']}**: {event['value'][:100]}...\n")

                    if len(connection_events) > 10:
                        f.write(f"  *(and {len(connection_events) - 10} more connection events)*\n")
                    f.write("\n")

            # Evidence examples
            f.write("\n## Evidence Examples\n\n")

            # Group by pattern type for clear organization
            for pattern_type in pattern_types.keys():
                f.write(f"### {pattern_type.title()} Evidence\n\n")

                type_events = [e for e in self.teamviewer_events if e['pattern_type'] == pattern_type]

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
                    f.write(f"  *(and {len(type_events) - 5} more {pattern_type} evidence items)*\n")

                f.write("\n")

            # Conclusions section
            f.write("## Conclusions\n\n")

            if not self.teamviewer_events:
                f.write("No evidence of TeamViewer activity was found in the system timeline data.\n")
            else:
                conclusions = []

                # Basic conclusion about TeamViewer presence
                conclusions.append(f"TeamViewer software was detected on the system with {len(self.teamviewer_events)} related artifacts.")

                # Timeline-based conclusions
                if timeline_analysis and timeline_analysis['events_with_time']:
                    earliest = timeline_analysis['events_with_time'][0]['datetime']
                    latest = timeline_analysis['events_with_time'][-1]['datetime']

                    # Check if TeamViewer was recently used
                    now = datetime.now()
                    if (now - latest).days < 30:
                        conclusions.append("TeamViewer was used recently (within the last 30 days).")

                    # Check for long-term usage
                    if (latest - earliest).days > 90:
                        conclusions.append("Evidence suggests long-term TeamViewer usage over multiple months.")

                    # Check for frequent usage
                    if len(timeline_analysis['activity_by_date']) > 10:
                        conclusions.append("TeamViewer was used frequently, on multiple dates.")

                    # Check for high-activity periods
                    high_activity_dates = {d: len(e) for d, e in timeline_analysis['activity_by_date'].items() if len(e) > 5}
                    if high_activity_dates:
                        conclusions.append(f"Intense TeamViewer activity was detected on {len(high_activity_dates)} dates.")

                # Pattern-based conclusions
                if 'registry' in pattern_types and pattern_types['registry'] > 0:
                    conclusions.append("Registry artifacts confirm TeamViewer installation.")

                if 'file_path' in pattern_types and pattern_types['file_path'] > 0:
                    conclusions.append("TeamViewer executable and configuration files were found on the system.")

                # Write all conclusions
                for conclusion in conclusions:
                    f.write(f"- {conclusion}\n")

                # Security recommendations
                f.write("\n### Security Recommendations\n\n")
                f.write("1. Verify whether TeamViewer installation was authorized and necessary\n")
                f.write("2. Review TeamViewer access logs for unauthorized connection attempts\n")
                f.write("3. Check TeamViewer configuration for password strength and access controls\n")
                f.write("4. Examine other system artifacts during periods of high TeamViewer activity for signs of malicious activity\n")
                f.write("5. Consider disabling or uninstalling TeamViewer if not required for legitimate business use\n")

        print(f"Generated TeamViewer analysis report at {report_path}")
        return report_path

    def analyze(self):
        """Main analysis function"""
        csv_files = self.find_csv_files()
        self.search_for_teamviewer(csv_files)
        timeline_analysis = self.analyze_teamviewer_timeline()
        report_path = self.generate_report(timeline_analysis)
        return report_path


def main():
    parser = argparse.ArgumentParser(description='Detect TeamViewer artifacts in system timeline data')
    parser.add_argument('--system-csv-dir', required=True, help='Directory containing system timeline CSV files')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run detector
    detector = TeamViewerDetector(args.system_csv_dir, args.output_dir)
    detector.analyze()
    print("Analysis complete!")


if __name__ == "__main__":
    main()