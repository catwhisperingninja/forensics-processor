#!/usr/bin/env python3
import os
import re
import pandas as pd
import argparse
from datetime import datetime
import glob
from pathlib import Path


class SystemTimelineAnalyzer:
    """Analyzes system timeline data from CSV files for forensic investigation"""

    def __init__(self, csv_dir, output_dir):
        self.csv_dir = csv_dir
        self.output_dir = output_dir
        self.event_data = []
        self.event_types = {}
        self.file_operations = []
        self.registry_events = []
        self.application_execution = []
        self.external_device_events = []

    def find_csv_files(self):
        """Find all CSV files in the specified directory"""
        csv_patterns = [
            os.path.join(self.csv_dir, "*.csv"),
            os.path.join(self.csv_dir, "**", "*.csv"),
        ]

        csv_files = []
        for pattern in csv_patterns:
            csv_files.extend(glob.glob(pattern, recursive=True))

        print(f"Found {len(csv_files)} CSV files to analyze")
        return csv_files

    def analyze_csv_structure(self):
        """Analyze the structure of the CSV files to understand data format"""
        csv_files = self.find_csv_files()
        file_structures = {}

        for csv_file in csv_files:
            try:
                # Read a small sample to analyze structure
                filename = Path(csv_file).name
                sample_data = pd.read_csv(csv_file, nrows=5)
                columns = list(sample_data.columns)

                # Store structure information
                file_structures[filename] = {
                    'columns': columns,
                    'path': csv_file,
                    'size_mb': os.path.getsize(csv_file) / (1024 * 1024)
                }

                print(f"Analyzed structure of {filename} - Columns: {', '.join(columns)}")
            except Exception as e:
                print(f"Error analyzing {csv_file}: {e}")

        return file_structures

    def sample_file_content(self, file_structures):
        """Sample content from different CSV files to understand data types"""
        samples = {}

        for filename, structure in file_structures.items():
            try:
                csv_path = structure['path']
                # For large files, only read a limited number of rows
                if structure['size_mb'] > 100:
                    print(f"Reading sample from large file {filename} ({structure['size_mb']:.2f} MB)")
                    df = pd.read_csv(csv_path, nrows=100)
                else:
                    print(f"Reading full content from {filename} ({structure['size_mb']:.2f} MB)")
                    df = pd.read_csv(csv_path)

                samples[filename] = {
                    'row_count': len(df),
                    'sample_rows': df.head(5).to_dict('records'),
                    'value_counts': {}
                }

                # If this is a frequency-type file (has count column)
                if 'count' in df.columns and 'value' in df.columns:
                    samples[filename]['top_values'] = df.sort_values('count', ascending=False).head(20).to_dict('records')

                # Get value counts for categorizing events
                for col in df.columns:
                    if df[col].dtype == 'object' and len(df) < 1000:
                        value_counts = df[col].value_counts().head(10).to_dict()
                        samples[filename]['value_counts'][col] = value_counts

            except Exception as e:
                print(f"Error sampling {filename}: {e}")

        return samples

    def identify_key_event_types(self, samples):
        """Identify key event types in the timeline data"""
        event_types = {}

        # First check timestamp_desc.csv which should contain event types
        if 'timestamp_desc.csv' in samples:
            if 'value' in samples['timestamp_desc.csv']['sample_rows'][0]:
                for row in samples['timestamp_desc.csv']['top_values']:
                    event_types[row['value']] = row['count']
                print(f"Found {len(event_types)} event types in timestamp_desc.csv")

        # Check source files for event sources
        if 'source.csv' in samples:
            sources = {}
            if 'value' in samples['source.csv']['sample_rows'][0]:
                for row in samples['source.csv']['top_values']:
                    sources[row['value']] = row['count']
                print(f"Found {len(sources)} event sources in source.csv")

        # Look for file operations in message files
        file_operations = []
        pattern_pairs = [
            (r'File reference: .* Update reason:', 'File Update'),
            (r'\.exe', 'Executable File'),
            (r'\.dll', 'Library File'),
            (r'File attribute flags:', 'File Attribute Change'),
            (r'USB', 'USB Device'),
            (r'INSTALL', 'Installation Event'),
            (r'\.log', 'Log File')
        ]

        # Search in message samples for patterns
        for filename, data in samples.items():
            if filename.startswith('message'):
                if 'value' in data['sample_rows'][0]:
                    for row in data['top_values']:
                        for pattern, event_type in pattern_pairs:
                            if re.search(pattern, str(row['value'])):
                                file_operations.append({
                                    'pattern': pattern,
                                    'type': event_type,
                                    'example': row['value'],
                                    'count': row['count']
                                })

        return {
            'event_types': event_types,
            'file_operations': file_operations
        }

    def generate_summary_report(self, file_structures, samples, event_data):
        """Generate a summary report of the system timeline data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"system_timeline_summary_{timestamp}.md")

        with open(report_path, 'w') as f:
            f.write("# System Timeline Data Analysis\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            # Overview of CSV files
            f.write("## CSV Files Overview\n\n")
            f.write("| Filename | Size (MB) | Column Count | Row Count |\n")
            f.write("|----------|-----------|--------------|----------|\n")

            for filename, structure in file_structures.items():
                row_count = samples[filename]['row_count'] if filename in samples else 'Unknown'
                f.write(f"| {filename} | {structure['size_mb']:.2f} | {len(structure['columns'])} | {row_count} |\n")

            f.write("\n\n")

            # Event Types
            f.write("## Event Types\n\n")

            if 'event_types' in event_data and event_data['event_types']:
                f.write("| Event Type | Count |\n")
                f.write("|------------|-------|\n")

                for event_type, count in event_data['event_types'].items():
                    f.write(f"| {event_type} | {count} |\n")
            else:
                f.write("*No event types identified*\n\n")

            f.write("\n\n")

            # File Operations
            f.write("## File Operations\n\n")

            if 'file_operations' in event_data and event_data['file_operations']:
                f.write("| Pattern | Type | Count | Example |\n")
                f.write("|---------|------|-------|--------|\n")

                for op in event_data['file_operations']:
                    # Truncate example if too long
                    example = op['example']
                    if len(str(example)) > 100:
                        example = str(example)[:97] + '...'
                    f.write(f"| {op['pattern']} | {op['type']} | {op['count']} | {example} |\n")
            else:
                f.write("*No file operations identified*\n\n")

            f.write("\n\n")

            # Sample Data
            f.write("## Sample Data\n\n")

            # Show samples from a few key files
            key_files = ['message_split-1_split-1.csv', 'timestamp_desc.csv', 'source.csv']
            for filename in key_files:
                if filename in samples:
                    f.write(f"### {filename}\n\n")
                    f.write("```\n")

                    # Print first few rows
                    for i, row in enumerate(samples[filename]['sample_rows']):
                        if i < 3:  # Limit to 3 samples
                            f.write(f"{row}\n")

                    f.write("```\n\n")

            f.write("\n## Next Steps\n\n")
            f.write("Based on this initial analysis, we recommend focusing on:\n\n")
            f.write("1. Extracting file operation events related to executable files and installations\n")
            f.write("2. Identifying USB device connections and file transfers\n")
            f.write("3. Analyzing log file entries for application activity\n")
            f.write("4. Correlating file operations with browser extension installation timestamps\n")
            f.write("5. Searching for Google Drive related file activities\n\n")

        print(f"Generated system timeline summary report at {report_path}")
        return report_path

    def analyze_timeline_data(self):
        """Main function to analyze system timeline data"""
        file_structures = self.analyze_csv_structure()
        samples = self.sample_file_content(file_structures)
        event_data = self.identify_key_event_types(samples)
        report_path = self.generate_summary_report(file_structures, samples, event_data)
        return report_path


def main():
    parser = argparse.ArgumentParser(description='Analyze system timeline data for forensic investigation')
    parser.add_argument('--csv-dir', required=True, help='Directory containing CSV timeline data files')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run analyzer
    analyzer = SystemTimelineAnalyzer(args.csv_dir, args.output_dir)
    analyzer.analyze_timeline_data()
    print("Analysis complete!")


if __name__ == "__main__":
    main()