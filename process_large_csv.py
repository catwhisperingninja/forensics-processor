#!/usr/bin/env python
"""
Process large CSV files in the batch analysis output.

This script:
1. Checks row counts for all CSV files in the batch_analysis/csv_output/categorical directory
2. Splits any files larger than 500,000 rows into smaller chunks
"""
import os
import sys
from data_processor.csv_splitter import check_csv_row_counts, split_csv


def main():
    """Main function."""
    # Directory containing batch analysis output
    batch_dir = "500k-csv-splits/batch_analysis"
    categorical_dir = os.path.join(batch_dir, "csv_output/categorical")

    # Check if the directory exists
    if not os.path.isdir(categorical_dir):
        print(f"Error: Directory not found: {categorical_dir}")
        return 1

    # Check row counts
    print(f"Checking row counts in {categorical_dir}...")
    counts = check_csv_row_counts(categorical_dir, recursive=False)

    # If no files found
    if not counts:
        print("No CSV files found")
        return 0

    # Print results
    print("\nRow counts:")
    print("-" * 80)
    print(f"{'File':<60} {'Rows':<10}")
    print("-" * 80)

    # Sort files by row count in descending order
    for file_path, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        rel_path = os.path.relpath(file_path, os.path.dirname(categorical_dir))
        print(f"{rel_path:<60} {count if count >= 0 else 'ERROR':<10}")

    print("-" * 80)

    # Find large files (> 500k rows) excluding already split files
    threshold = 500000
    large_files = []
    for file_path, count in counts.items():
        if count > threshold and "_split" not in file_path:
            large_files.append((file_path, count))

    if not large_files:
        print(f"No original CSV files exceed the {threshold} row threshold")
        return 0

    print(f"\nFound {len(large_files)} original files exceeding {threshold} rows:")
    for file_path, count in large_files:
        rel_path = os.path.relpath(file_path, os.path.dirname(categorical_dir))
        print(f"- {rel_path}: {count} rows")

    # Process all large files
    success_count = 0

    for file_path, file_rows in large_files:
        file_name = os.path.basename(file_path)
        print(f"\nSplitting {file_name} ({file_rows} rows) into {threshold}-row chunks...")

        # Split the file
        output_prefix = os.path.join(os.path.dirname(file_path), f"{os.path.splitext(file_name)[0]}_split")
        result = split_csv(
            input_file=file_path,
            output_prefix=output_prefix,
            max_rows_per_file=threshold,
            excel_output=False  # Skip Excel output for very large files
        )

        if result.get("success"):
            print(f"\nSuccessfully split {file_name}")
            print(f"Created {result['num_files']} CSV files:")
            for file_info in result.get("output_files", []):
                print(f"- {os.path.basename(file_info['csv_path'])}: "
                      f"approximately {file_info['approx_rows']} rows")
            print(f"Time taken: {result.get('elapsed_time', 0):.2f} seconds")
            success_count += 1
        else:
            print(f"Error splitting {file_name}: {result.get('error', 'Unknown error')}")

    print(f"\nCompleted splitting {success_count} of {len(large_files)} files")
    return 0 if success_count == len(large_files) else 1


if __name__ == "__main__":
    sys.exit(main())