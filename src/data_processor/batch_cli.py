"""
Command-line interface for batch processing large CSV datasets.
"""
import os
import argparse
from data_processor.batch_processor import batch_analyze_directory, MAX_ROWS_PER_FILE
from data_processor.post_processor import post_process_batch_results


def main():
    """Main function for CLI."""
    parser = argparse.ArgumentParser(description='Batch CSV Processor for Large Datasets')

    parser.add_argument('--input-dir', required=True,
                        help='Directory containing CSV chunk files')

    parser.add_argument('--output-dir',
                        help='Directory to save output files (defaults to input-dir/batch_analysis)')

    parser.add_argument('--max-chunks', type=int,
                        help='Maximum number of chunks to process (default: all)')

    parser.add_argument('--columns', nargs='+',
                        help='Specific columns to analyze (default: all columns)')

    parser.add_argument('--mode', choices=['streaming', 'individual'], default='streaming',
                        help='Processing mode: streaming (analyze all chunks together) or individual (analyze each chunk separately)')

    parser.add_argument('--output-format', choices=['excel', 'csv', 'both'], default='excel',
                        help='Output format: excel, csv, or both (default: excel)')

    parser.add_argument('--post-process', action='store_true',
                        help='Generate visualizations from batch analysis results using post-processor')

    # Add options for auto-splitting large CSV files
    parser.add_argument('--no-auto-split', action='store_true',
                        help='Disable automatic splitting of large CSV files')

    parser.add_argument('--split-threshold', type=int, default=MAX_ROWS_PER_FILE,
                        help=f'Row count threshold for splitting files (default: {MAX_ROWS_PER_FILE})')

    args = parser.parse_args()

    print(f"Starting batch analysis of CSV files in: {args.input_dir}")

    # Validate input directory
    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' does not exist.")
        return 1

    # Run batch analysis
    try:
        streaming_mode = args.mode == 'streaming'

        # Ensure we have CSV output if post-processing is requested
        output_format = args.output_format
        if args.post_process and output_format == 'excel':
            print("Post-processing requires CSV output. Changing output format to 'both'.")
            output_format = 'both'

        # Configure auto-split settings
        auto_split = not args.no_auto_split
        split_threshold = args.split_threshold

        if auto_split:
            print(f"Automatic file splitting is enabled (threshold: {split_threshold} rows)")
        else:
            print("Automatic file splitting is disabled")

        result_dir = batch_analyze_directory(
            chunk_dir=args.input_dir,
            output_dir=args.output_dir,
            max_chunks=args.max_chunks,
            streaming_mode=streaming_mode,
            columns_to_analyze=args.columns,
            output_format=output_format,
            auto_split=auto_split,
            split_threshold=split_threshold
        )

        print(f"Analysis complete! Results saved to: {result_dir}")

        # Run post-processing if requested
        if args.post_process:
            print("Starting post-processing to generate visualizations...")

            # Define CSV directory path
            csv_dir = os.path.join(result_dir, 'csv_output')
            if not os.path.exists(csv_dir):
                print(f"Error: CSV output not found at {csv_dir}")
                return 1

            # Define visualization output directory
            viz_dir = os.path.join(result_dir, 'visualizations')

            # Run post-processing
            try:
                excel_path = post_process_batch_results(csv_dir, viz_dir)
                print(f"Post-processing complete! Visualizations saved to: {excel_path}")
            except Exception as e:
                print(f"Error during post-processing: {str(e)}")
                return 1

        return 0

    except Exception as e:
        print(f"Error during batch processing: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())