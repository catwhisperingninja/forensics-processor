#!/usr/bin/env python
"""
Command-line tool for splitting large CSV files into smaller chunks and checking row counts.
"""
import os
import sys
import argparse
from typing import List
from data_processor.csv_splitter import split_csv, check_csv_row_counts

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description=(
            'CSV File Processing Tools - '
            'Split large CSV files into smaller chunks and check row counts'
        )
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Split command
    split_parser = subparsers.add_parser('split', help='Split a large CSV file into smaller chunks')
    split_parser.add_argument('--input-file', required=True, help='Path to the input CSV file')
    split_parser.add_argument('--output-prefix', help='Prefix for output files (default: based on input filename)')
    split_parser.add_argument('--max-rows', type=int, default=500000, help='Maximum rows per output file (default: 500000)')
    split_parser.add_argument('--chunk-size', type=int, default=5000, help='Rows to read at a time (default: 5000)')
    split_parser.add_argument('--excel', action='store_true', help='Create Excel outputs in addition to CSV')
    split_parser.add_argument('--diagnostic', action='store_true', help='Run in diagnostic mode')

    # Check command
    check_parser = subparsers.add_parser('check', help='Check row counts of CSV files in a directory')
    check_parser.add_argument('--dir', required=True, help='Directory to check CSV row counts')
    check_parser.add_argument('--recursive', action='store_true', help='Scan subdirectories recursively')
    check_parser.add_argument('--threshold', type=int, default=500000, help='Row count threshold (default: 500000)')

    # Fix command to specifically handle large files
    fix_parser = subparsers.add_parser('fix', help='Automatically find and split large CSV files')
    fix_parser.add_argument('--dir', required=True, help='Directory to scan for large CSV files')
    fix_parser.add_argument('--recursive', action='store_true', help='Scan subdirectories recursively')
    fix_parser.add_argument('--threshold', type=int, default=500000, help='Row count threshold (default: 500000)')
    fix_parser.add_argument('--excel', action='store_true', help='Create Excel outputs in addition to CSV')

    args = parser.parse_args()

    if args.command == 'split':
        # Split a single CSV file
        result = split_csv(
            input_file=args.input_file,
            output_prefix=args.output_prefix,
            max_rows_per_file=args.max_rows,
            chunk_size=args.chunk_size,
            excel_output=args.excel,
            diagnostic_mode=args.diagnostic
        )

        if result.get("success"):
            return 0
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
            return 1

    elif args.command == 'check':
        # Check row counts in a directory
        if not os.path.isdir(args.dir):
            print(f"Error: Directory not found: {args.dir}")
            return 1

        print(f"Checking CSV row counts in {args.dir}...")
        counts = check_csv_row_counts(args.dir, args.recursive)

        if not counts:
            print("No CSV files found")
            return 0

        # Print results
        print("\nRow counts:")
        print("-" * 80)
        print(f"{'File':<60} {'Rows':<10}")
        print("-" * 80)

        for file_path, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            rel_path = os.path.relpath(file_path, args.dir)
            print(f"{rel_path:<60} {count if count >= 0 else 'ERROR':<10}")

        print("-" * 80)
        threshold = args.threshold
        large_files = [(f, c) for f, c in counts.items() if c > threshold]
        if large_files:
            print(f"\nFiles exceeding {threshold} rows:")
            for file_path, count in large_files:
                rel_path = os.path.relpath(file_path, args.dir)
                print(f"- {rel_path}: {count} rows")

        return 0

    elif args.command == 'fix':
        # Find and split large CSV files
        if not os.path.isdir(args.dir):
            print(f"Error: Directory not found: {args.dir}")
            return 1

        print(f"Scanning for large CSV files in {args.dir}...")
        counts = check_csv_row_counts(args.dir, args.recursive)

        if not counts:
            print("No CSV files found")
            return 0

        # Find large files
        large_files = [(f, c) for f, c in counts.items() if c > args.threshold]
        if not large_files:
            print(f"No CSV files exceed the {args.threshold} row threshold")
            return 0

        print(f"\nFound {len(large_files)} files exceeding {args.threshold} rows:")
        for file_path, count in large_files:
            rel_path = os.path.relpath(file_path, args.dir)
            print(f"- {rel_path}: {count} rows")

        print("\nProcessing large files...")

        # Process each large file
        success_count = 0
        for file_path, _ in large_files:
            print(f"\nSplitting {os.path.basename(file_path)}:")
            result = split_csv(
                input_file=file_path,
                output_prefix=None,  # Use default based on filename
                max_rows_per_file=args.threshold,
                excel_output=args.excel
            )

            if result.get("success"):
                success_count += 1
            else:
                print(f"  Error: {result.get('error', 'Unknown error')}")

        print(f"\nCompleted splitting {success_count} of {len(large_files)} files")
        return 0 if success_count == len(large_files) else 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())