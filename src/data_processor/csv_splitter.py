"""
CSV Splitter module for splitting large CSV files into smaller chunks.
"""
import os
import pandas as pd
import sys
from typing import Optional, List, Dict, Any
import time
import argparse


def split_csv(
    input_file: str,
    output_prefix: Optional[str] = None,
    max_rows_per_file: int = 500000,
    chunk_size: int = 5000,
    excel_output: bool = True,
    diagnostic_mode: bool = False
) -> Dict[str, Any]:
    """
    Split a large CSV file into smaller chunks of specified size.

    Args:
        input_file: Path to the input CSV file
        output_prefix: Prefix for output files (default: based on input filename)
        max_rows_per_file: Maximum rows per output file
        chunk_size: Number of rows to read at a time
        excel_output: Whether to create Excel files in addition to CSV
        diagnostic_mode: Whether to run in diagnostic mode

    Returns:
        Dictionary with information about the splitting operation
    """
    start_time = time.time()
    results = {
        "input_file": input_file,
        "output_files": [],
        "total_rows": 0,
        "num_files": 0,
        "success": False,
        "error": None
    }

    # Run diagnostics if requested
    if diagnostic_mode:
        print("=== DIAGNOSTIC MODE ===")
        print(f"Python: {sys.version}")
        print(f"Pandas: {pd.__version__}")
        import platform
        print(f"OS: {platform.system()} {platform.version()}")

        # Check memory
        try:
            import psutil
            mem = psutil.virtual_memory()
            free_mem_gb = round(mem.available / (1024 ** 3), 2)
            print(f"Free memory: {free_mem_gb} GB")
        except ImportError:
            print("psutil not installed, can't check memory")

        return {"diagnostic_mode": True}

    # Validate file exists
    if not os.path.exists(input_file):
        results["error"] = f"Input file not found: {input_file}"
        return results

    # Create output prefix if not specified
    if not output_prefix:
        filename = os.path.basename(input_file)
        output_prefix = os.path.splitext(filename)[0] + "_split"

    try:
        # Get total number of rows in file (using a more memory-efficient approach)
        print(f"Counting rows in {input_file}...")
        total_rows = sum(1 for _ in open(input_file, 'r'))
        header_row = True  # First row is assumed to be a header
        data_rows = total_rows - 1 if header_row else total_rows
        print(f"Total rows: {total_rows} (data rows: {data_rows})")

        results["total_rows"] = data_rows

        # Calculate number of files needed
        num_files = (data_rows + max_rows_per_file - 1) // max_rows_per_file
        print(f"Will create {num_files} files (both CSV and Excel)")

        results["num_files"] = num_files

        # Read CSV in chunks and write to output files
        current_file_num = 1
        current_chunk_rows = 0
        current_output_rows = 0
        header = None

        # Prepare the first output file
        base_output_path = f"{output_prefix}-{current_file_num}"
        csv_output_path = f"{base_output_path}.csv"
        excel_output_path = f"{base_output_path}.xlsx" if excel_output else None

        # Dictionary to store current file chunks
        current_file_chunks = []
        output_files = []

        # Process the input file in chunks
        for chunk in pd.read_csv(input_file, chunksize=chunk_size):
            if header is None and header_row:
                header = chunk.columns.tolist()

            # Add chunk to current file chunks
            current_file_chunks.append(chunk)
            current_chunk_rows = len(chunk)
            current_output_rows += current_chunk_rows

            # Check if we need to write current chunks to a file
            if current_output_rows >= max_rows_per_file or (current_file_num == num_files and current_file_chunks):
                print(f"Creating file {current_file_num} (approximately {current_output_rows} rows)")

                # Combine chunks for current file
                combined_df = pd.concat(current_file_chunks, ignore_index=True)

                # Create CSV file
                combined_df.to_csv(csv_output_path, index=False)
                print(f"  Created CSV: {csv_output_path}")

                # Create Excel file if requested
                if excel_output:
                    combined_df.to_excel(excel_output_path, index=False, engine='openpyxl')
                    print(f"  Created Excel: {excel_output_path}")

                # Track output files
                file_info = {
                    "file_num": current_file_num,
                    "csv_path": csv_output_path,
                    "excel_path": excel_output_path if excel_output else None,
                    "approx_rows": current_output_rows
                }
                output_files.append(file_info)

                # Reset for next file
                current_file_chunks = []
                current_output_rows = 0
                current_file_num += 1

                # Prepare next output file if needed
                if current_file_num <= num_files:
                    base_output_path = f"{output_prefix}-{current_file_num}"
                    csv_output_path = f"{base_output_path}.csv"
                    excel_output_path = f"{base_output_path}.xlsx" if excel_output else None

        # Update results
        results["output_files"] = output_files
        results["success"] = True
        results["elapsed_time"] = time.time() - start_time

        print(f"Done! Created {num_files} CSV files and {num_files if excel_output else 0} Excel files.")
        return results

    except Exception as e:
        results["error"] = str(e)
        print(f"Error processing file: {str(e)}")
        return results


def count_csv_rows(csv_file: str) -> int:
    """
    Count the number of rows in a CSV file using an efficient method.

    Args:
        csv_file: Path to the CSV file

    Returns:
        Number of rows in the file (including header)
    """
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            row_count = sum(1 for _ in f)
        return row_count
    except Exception as e:
        print(f"Error counting rows in {csv_file}: {str(e)}")
        return -1


def check_csv_row_counts(directory: str, recursive: bool = False) -> Dict[str, int]:
    """
    Check row counts of all CSV files in a directory.

    Args:
        directory: Directory path to scan
        recursive: Whether to scan subdirectories recursively

    Returns:
        Dictionary mapping file paths to row counts
    """
    results = {}

    if recursive:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.csv'):
                    file_path = os.path.join(root, file)
                    results[file_path] = count_csv_rows(file_path)
    else:
        for file in os.listdir(directory):
            if file.lower().endswith('.csv'):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path):
                    results[file_path] = count_csv_rows(file_path)

    return results


def main():
    """Main function for CLI."""
    parser = argparse.ArgumentParser(description='Split large CSV files into smaller chunks')

    parser.add_argument('--input-file', help='Path to the input CSV file')
    parser.add_argument('--output-prefix', help='Prefix for output files')
    parser.add_argument('--max-rows', type=int, default=500000, help='Maximum rows per output file')
    parser.add_argument('--chunk-size', type=int, default=5000, help='Rows to read at a time')
    parser.add_argument('--excel', action='store_true', help='Create Excel outputs in addition to CSV')
    parser.add_argument('--diagnostic', action='store_true', help='Run in diagnostic mode')
    parser.add_argument('--check-dir', help='Directory to check CSV row counts')
    parser.add_argument('--recursive', action='store_true', help='Scan subdirectories recursively')

    args = parser.parse_args()

    # Either process an input file or check row counts in a directory
    if args.input_file:
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
        return 1
    elif args.check_dir:
        if not os.path.isdir(args.check_dir):
            print(f"Error: Directory not found: {args.check_dir}")
            return 1

        print(f"Checking CSV row counts in {args.check_dir}...")
        counts = check_csv_row_counts(args.check_dir, args.recursive)

        if not counts:
            print("No CSV files found")
            return 0

        # Print results
        print("\nRow counts:")
        print("-" * 80)
        print(f"{'File':<60} {'Rows':<10}")
        print("-" * 80)

        for file_path, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            rel_path = os.path.relpath(file_path, args.check_dir)
            print(f"{rel_path:<60} {count if count >= 0 else 'ERROR':<10}")

        print("-" * 80)
        large_files = [(f, c) for f, c in counts.items() if c > 500000]
        if large_files:
            print("\nFiles exceeding 500,000 rows:")
            for file_path, count in large_files:
                rel_path = os.path.relpath(file_path, args.check_dir)
                print(f"- {rel_path}: {count} rows")

        return 0
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())