#!/usr/bin/env python3
import os
import sys
import glob
import argparse
import subprocess
from datetime import datetime

def main():
    """Main function to analyze all URL files found in the dataset"""
    parser = argparse.ArgumentParser(description='Process all URL files in a directory')
    parser.add_argument('--source-dir', required=True, help='Directory containing URL CSV files')
    parser.add_argument('--output-dir', required=True, help='Base output directory for reports')

    args = parser.parse_args()

    # Find all URL CSV files
    url_files = glob.glob(os.path.join(args.source_dir, '**', '*urls_*.csv'), recursive=True)

    if not url_files:
        print(f"No URL files found in {args.source_dir}")
        sys.exit(1)

    print(f"Found {len(url_files)} URL files to analyze")

    # Create timestamp for run
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.output_dir, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    # Process each file
    for i, url_file in enumerate(url_files):
        print(f"Processing file {i+1}/{len(url_files)}: {url_file}")

        # Create a subdirectory for each file's results
        file_basename = os.path.basename(url_file).replace('.csv', '')
        file_output_dir = os.path.join(run_dir, file_basename)
        os.makedirs(file_output_dir, exist_ok=True)

        # Run the suspicious URL analyzer on this file
        analyzer_script = os.path.join(os.path.dirname(__file__), "suspicious_url_analyzer.py")
        cmd = [
            "python3",
            analyzer_script,
            "--url-csv", url_file,
            "--output-dir", file_output_dir
        ]

        try:
            subprocess.run(cmd, check=True)
            print(f"Successfully analyzed {url_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error processing {url_file}: {e}")

    print(f"Analysis complete! Results are in {run_dir}")

    # Generate an index file for all the results
    generate_index(run_dir, url_files)

def generate_index(run_dir, processed_files):
    """Generate an index file for all processed files"""
    index_path = os.path.join(run_dir, "index.md")

    with open(index_path, 'w') as f:
        f.write("# URL Analysis Results\n\n")
        f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

        f.write("## Processed Files\n\n")

        for i, url_file in enumerate(processed_files):
            file_basename = os.path.basename(url_file).replace('.csv', '')
            summary_file = os.path.join(run_dir, file_basename, "summary_report_*.md")
            summary_files = glob.glob(summary_file)

            if summary_files:
                summary_link = os.path.relpath(summary_files[0], run_dir)
                f.write(f"{i+1}. [{file_basename}]({summary_link})\n")
            else:
                f.write(f"{i+1}. {file_basename} (No summary report found)\n")

    print(f"Generated index at {index_path}")

if __name__ == "__main__":
    main()