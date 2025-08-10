"""
Batch Processor module for handling large CSV datasets in chunks.
"""
import os
import glob
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Union, Literal
from .analyzer import DataAnalyzer, analyze_file
from .csv_splitter import split_csv, count_csv_rows

# Maximum number of rows per file for efficient processing
MAX_ROWS_PER_FILE = 500000

class BatchProcessor:
    """Process multiple CSV files in batch and aggregate results."""

    def __init__(self, chunk_dir: str, output_dir: str = None, output_format: str = "excel",
                 auto_split: bool = True, split_threshold: int = MAX_ROWS_PER_FILE):
        """
        Initialize the batch processor.

        Args:
            chunk_dir: Directory containing CSV chunk files
            output_dir: Directory to save output files (defaults to chunk_dir/output)
            output_format: Format for output files - 'excel', 'csv', or 'both' (default: 'excel')
            auto_split: Whether to automatically split large CSV files (default: True)
            split_threshold: Row count threshold for splitting files (default: 500,000)
        """
        self.chunk_dir = chunk_dir
        self.output_dir = output_dir or os.path.join(chunk_dir, 'batch_analysis')
        self.auto_split = auto_split
        self.split_threshold = split_threshold

        # Validate output format
        if output_format not in ['excel', 'csv', 'both']:
            raise ValueError("output_format must be one of: 'excel', 'csv', 'both'")
        self.output_format = output_format

        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

        # Get list of chunk files
        self.chunk_files = glob.glob(os.path.join(chunk_dir, '*.csv'))
        if not self.chunk_files:
            raise ValueError(f"No CSV files found in {chunk_dir}")

        print(f"Found {len(self.chunk_files)} CSV chunk files")

        # Check and split large files if auto_split is enabled
        if self.auto_split:
            self._auto_split_large_files()

    def _auto_split_large_files(self) -> List[str]:
        """
        Automatically detect and split large CSV files.

        Returns:
            List of paths to newly created CSV files
        """
        new_files = []
        large_files = []

        # Check file sizes
        print("Checking for large CSV files that need splitting...")
        for file_path in self.chunk_files:
            # Skip files that are already split
            if "_split-" in os.path.basename(file_path):
                continue

            row_count = count_csv_rows(file_path)
            if row_count > self.split_threshold:
                large_files.append((file_path, row_count))

        if not large_files:
            print("No large CSV files found that need splitting.")
            return new_files

        # Split large files
        print(f"Found {len(large_files)} CSV files exceeding {self.split_threshold} rows:")
        for file_path, row_count in large_files:
            file_name = os.path.basename(file_path)
            print(f"Splitting {file_name} ({row_count} rows) into {self.split_threshold}-row chunks...")

            # Create output prefix
            output_prefix = os.path.join(
                os.path.dirname(file_path),
                f"{os.path.splitext(file_name)[0]}_split"
            )

            # Split the file
            result = split_csv(
                input_file=file_path,
                output_prefix=output_prefix,
                max_rows_per_file=self.split_threshold,
                excel_output=False  # Skip Excel output for batch processing
            )

            if result.get("success"):
                print(f"Successfully split {file_name}")
                # Add new files to the list
                for file_info in result.get("output_files", []):
                    csv_path = file_info.get("csv_path")
                    if csv_path:
                        new_files.append(csv_path)
            else:
                print(f"Error splitting {file_name}: {result.get('error', 'Unknown error')}")

        # Update chunk files list with new files
        if new_files:
            print(f"Added {len(new_files)} new split files to processing list")
            self.chunk_files.extend(new_files)

        return new_files

    def analyze_chunks(self, max_chunks: Optional[int] = None) -> Dict[str, Any]:
        """
        Analyze each chunk file separately and store results.

        Args:
            max_chunks: Maximum number of chunks to process (None for all)

        Returns:
            Dictionary with analysis results for each chunk
        """
        results = {}

        # Process chunks (limited by max_chunks if specified)
        chunks_to_process = self.chunk_files[:max_chunks] if max_chunks else self.chunk_files

        for i, chunk_file in enumerate(chunks_to_process):
            print(f"Processing chunk {i+1}/{len(chunks_to_process)}: {os.path.basename(chunk_file)}")

            # Create chunk-specific output directory
            chunk_name = os.path.splitext(os.path.basename(chunk_file))[0]
            chunk_output_dir = os.path.join(self.output_dir, chunk_name)
            os.makedirs(chunk_output_dir, exist_ok=True)

            # Analyze chunk
            try:
                chunk_results = analyze_file(chunk_file, chunk_output_dir)
                results[chunk_name] = chunk_results
                print(f"  Analysis complete. Results saved to: {chunk_results['output_file']}")
            except Exception as e:
                print(f"  Error analyzing chunk {chunk_name}: {str(e)}")
                results[chunk_name] = {"error": str(e)}

        return results

    def aggregate_statistics(self, max_chunks: Optional[int] = None) -> Dict[str, pd.DataFrame]:
        """
        Process chunks to create aggregate statistics without loading all data at once.

        Args:
            max_chunks: Maximum number of chunks to process (None for all)

        Returns:
            Dictionary with aggregated statistics
        """
        chunks_to_process = self.chunk_files[:max_chunks] if max_chunks else self.chunk_files

        # Initialize aggregation containers
        aggregated = {
            'summary_stats': {
                'count': 0,
                'sum': 0,
                'min': {},
                'max': {},
                'mean': 0,
                'missing_count': {},
                'total_rows': 0
            },
            'categorical_counts': {},
            'missing_data': {},
            'outlier_counts': {},
        }

        # Process each chunk for aggregation
        for i, chunk_file in enumerate(chunks_to_process):
            print(f"Aggregating statistics from chunk {i+1}/{len(chunks_to_process)}")
            chunk_name = os.path.splitext(os.path.basename(chunk_file))[0]

            try:
                # Read chunk with optimized settings
                df_chunk = pd.read_csv(
                    chunk_file,
                    low_memory=True  # Use less memory
                )

                # Update total rows
                chunk_rows = len(df_chunk)
                aggregated['summary_stats']['total_rows'] += chunk_rows

                # Process numeric columns
                numeric_cols = df_chunk.select_dtypes(include=['number']).columns
                for col in numeric_cols:
                    # Initialize column stats if first encounter
                    if col not in aggregated['summary_stats']['min']:
                        aggregated['summary_stats']['min'][col] = float('inf')
                        aggregated['summary_stats']['max'][col] = float('-inf')
                        aggregated['summary_stats']['missing_count'][col] = 0

                    # Update min/max
                    col_min = df_chunk[col].min()
                    col_max = df_chunk[col].max()
                    if not pd.isna(col_min) and col_min < aggregated['summary_stats']['min'][col]:
                        aggregated['summary_stats']['min'][col] = col_min
                    if not pd.isna(col_max) and col_max > aggregated['summary_stats']['max'][col]:
                        aggregated['summary_stats']['max'][col] = col_max

                    # Update missing counts
                    missing = df_chunk[col].isna().sum()
                    aggregated['summary_stats']['missing_count'][col] += missing

                # Process categorical columns
                cat_cols = df_chunk.select_dtypes(exclude=['number']).columns
                for col in cat_cols:
                    if col not in aggregated['categorical_counts']:
                        aggregated['categorical_counts'][col] = {}

                    # Update value counts
                    value_counts = df_chunk[col].value_counts(dropna=False)
                    for value, count in value_counts.items():
                        if value not in aggregated['categorical_counts'][col]:
                            aggregated['categorical_counts'][col][value] = 0
                        aggregated['categorical_counts'][col][value] += count

                # Update missing data
                for col in df_chunk.columns:
                    if col not in aggregated['missing_data']:
                        aggregated['missing_data'][col] = 0
                    aggregated['missing_data'][col] += df_chunk[col].isna().sum()

                print(f"  Processed {chunk_rows} rows from {chunk_name}")

            except Exception as e:
                print(f"  Error processing chunk {chunk_name} for aggregation: {str(e)}")

        # Convert aggregated results to DataFrames
        result_dfs = {}

        # Summary stats
        total_rows = aggregated['summary_stats']['total_rows']

        # Convert missing data to DataFrame
        missing_df = pd.DataFrame({
            'column': list(aggregated['missing_data'].keys()),
            'missing_count': list(aggregated['missing_data'].values()),
        })
        missing_df['missing_percentage'] = (missing_df['missing_count'] / total_rows) * 100
        missing_df = missing_df.sort_values('missing_percentage', ascending=False)
        result_dfs['missing_data'] = missing_df

        # Convert categorical counts to DataFrames
        cat_dfs = {}
        for col, counts in aggregated['categorical_counts'].items():
            cat_df = pd.DataFrame({
                'value': list(counts.keys()),
                'count': list(counts.values()),
            })
            cat_df['percentage'] = (cat_df['count'] / total_rows) * 100
            cat_df = cat_df.sort_values('count', ascending=False)
            cat_dfs[col] = cat_df

        result_dfs['categorical_summary'] = cat_dfs

        # Add total row count
        result_dfs['total_rows'] = total_rows

        # Export aggregated results
        self._export_aggregate_results(result_dfs)

        return result_dfs

    def _export_aggregate_results(self, results: Dict[str, Any]) -> Dict[str, str]:
        """
        Export aggregated results to specified format(s).

        Args:
            results: Dictionary with aggregated results

        Returns:
            Dictionary with paths to the output files by format
        """
        output_files = {}

        # Define base filename
        base_filename = os.path.join(self.output_dir, 'aggregated_analysis')

        # Excel output
        if self.output_format in ['excel', 'both']:
            excel_file = f"{base_filename}.xlsx"
            with pd.ExcelWriter(excel_file) as writer:
                # Overall info
                pd.DataFrame({
                    'Metric': ['Total Rows', 'CSV Chunks Processed'],
                    'Value': [results['total_rows'], len(self.chunk_files)]
                }).to_excel(writer, sheet_name='Info', index=False)

                # Missing data
                results['missing_data'].to_excel(writer, sheet_name='Missing_Data', index=False)

                # Categorical summaries (top values only)
                if results['categorical_summary']:
                    for i, (col, df) in enumerate(results['categorical_summary'].items()):
                        # Limit to top 1000 values to avoid Excel limitations
                        df_limited = df.head(1000)

                        # Sanitize sheet name
                        sheet_name = f"Cat_{i+1}_{col[:10]}"
                        sheet_name = sheet_name.replace(':', '_').replace('\\', '_').replace('/', '_') \
                                            .replace('?', '_').replace('*', '_').replace('[', '_') \
                                            .replace(']', '_')

                        df_limited.to_excel(writer, sheet_name=sheet_name, index=False)

            output_files['excel'] = excel_file
            print(f"Aggregated results saved to Excel: {excel_file}")

        # CSV output
        if self.output_format in ['csv', 'both']:
            # Create CSV directory
            csv_dir = os.path.join(self.output_dir, 'csv_output')
            os.makedirs(csv_dir, exist_ok=True)

            # Info CSV
            info_file = os.path.join(csv_dir, 'info.csv')
            pd.DataFrame({
                'Metric': ['Total Rows', 'CSV Chunks Processed'],
                'Value': [results['total_rows'], len(self.chunk_files)]
            }).to_csv(info_file, index=False)

            # Missing data CSV
            missing_file = os.path.join(csv_dir, 'missing_data.csv')
            results['missing_data'].to_csv(missing_file, index=False)

            # Categorical summaries
            if results['categorical_summary']:
                cat_dir = os.path.join(csv_dir, 'categorical')
                os.makedirs(cat_dir, exist_ok=True)

                for col, df in results['categorical_summary'].items():
                    # Sanitize filename
                    safe_col_name = col.replace(':', '_').replace('\\', '_').replace('/', '_') \
                                      .replace('?', '_').replace('*', '_').replace('[', '_') \
                                      .replace(']', '_')
                    cat_file = os.path.join(cat_dir, f"{safe_col_name}.csv")
                    df.to_csv(cat_file, index=False)

            output_files['csv'] = csv_dir
            print(f"Aggregated results saved to CSV directory: {csv_dir}")

        return output_files

    def process_in_streaming_mode(self, columns_to_analyze: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Process entire dataset in streaming mode without loading all data at once.

        Args:
            columns_to_analyze: Specific columns to analyze (None for all)

        Returns:
            Dictionary with analysis results
        """
        # Get schema from first chunk to identify numeric/categorical columns
        first_chunk = pd.read_csv(self.chunk_files[0], nrows=10)

        if columns_to_analyze:
            # Filter to only include requested columns that exist in the data
            columns_to_analyze = [col for col in columns_to_analyze if col in first_chunk.columns]
            if not columns_to_analyze:
                raise ValueError("None of the specified columns exist in the data")
        else:
            # Use all columns
            columns_to_analyze = first_chunk.columns.tolist()

        # Identify numeric and categorical columns
        numeric_cols = [col for col in columns_to_analyze
                        if col in first_chunk.select_dtypes(include=['number']).columns]
        cat_cols = [col for col in columns_to_analyze
                    if col in first_chunk.select_dtypes(exclude=['number']).columns]

        print(f"Streaming analysis of {len(self.chunk_files)} chunks")
        print(f"Analyzing {len(numeric_cols)} numeric columns and {len(cat_cols)} categorical columns")

        # Initialize aggregates
        results = {
            'total_rows': 0,
            'numeric_stats': {col: {'sum': 0, 'sum_sq': 0, 'min': float('inf'), 'max': float('-inf'),
                                   'count': 0, 'missing': 0} for col in numeric_cols},
            'categorical_counts': {col: {} for col in cat_cols},
            'missing_counts': {col: 0 for col in columns_to_analyze}
        }

        # Process each chunk
        for i, chunk_file in enumerate(self.chunk_files):
            print(f"Streaming chunk {i+1}/{len(self.chunk_files)}: {os.path.basename(chunk_file)}")

            # Read chunk with only specified columns
            try:
                chunk = pd.read_csv(chunk_file, usecols=columns_to_analyze, low_memory=True)

                # Update total rows
                chunk_rows = len(chunk)
                results['total_rows'] += chunk_rows

                # Process numeric columns
                for col in numeric_cols:
                    # Skip if column doesn't exist in this chunk
                    if col not in chunk.columns:
                        continue

                    # Get non-missing values
                    non_missing = chunk[col].dropna()

                    # Update statistics
                    if len(non_missing) > 0:
                        results['numeric_stats'][col]['sum'] += non_missing.sum()
                        results['numeric_stats'][col]['sum_sq'] += (non_missing ** 2).sum()
                        results['numeric_stats'][col]['min'] = min(results['numeric_stats'][col]['min'], non_missing.min())
                        results['numeric_stats'][col]['max'] = max(results['numeric_stats'][col]['max'], non_missing.max())
                        results['numeric_stats'][col]['count'] += len(non_missing)

                    # Update missing count
                    missing = chunk[col].isna().sum()
                    results['numeric_stats'][col]['missing'] += missing
                    results['missing_counts'][col] += missing

                # Process categorical columns
                for col in cat_cols:
                    # Skip if column doesn't exist in this chunk
                    if col not in chunk.columns:
                        continue

                    # Update value counts
                    value_counts = chunk[col].value_counts(dropna=False)
                    for value, count in value_counts.items():
                        if value not in results['categorical_counts'][col]:
                            results['categorical_counts'][col][value] = 0
                        results['categorical_counts'][col][value] += count

                    # Update missing count
                    if col not in results['missing_counts']:
                        results['missing_counts'][col] = 0
                    results['missing_counts'][col] += chunk[col].isna().sum()

                print(f"  Processed {chunk_rows} rows")

            except Exception as e:
                print(f"  Error processing chunk: {str(e)}")

        # Calculate final statistics
        final_results = self._calculate_final_statistics(results)

        # Base filename for outputs
        base_filename = os.path.join(self.output_dir, 'streaming_analysis')

        # Export results in the specified format(s)
        output_files = {}

        if self.output_format in ['excel', 'both']:
            excel_file = f"{base_filename}.xlsx"
            self._export_streaming_results(final_results, excel_file)
            output_files['excel'] = excel_file

        if self.output_format in ['csv', 'both']:
            csv_dir = os.path.join(self.output_dir, 'csv_output')
            self._export_streaming_results_csv(final_results, csv_dir)
            output_files['csv'] = csv_dir

        final_results['output_files'] = output_files
        return final_results

    def _calculate_final_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate final statistics from aggregated results."""
        final_results = {
            'total_rows': results['total_rows'],
            'numeric_summary': {},
            'categorical_summary': {},
            'missing_data': pd.DataFrame()
        }

        # Process numeric statistics
        numeric_summary = {}
        for col, stats in results['numeric_stats'].items():
            # Skip columns with no data
            if stats['count'] == 0:
                continue

            col_summary = {
                'count': stats['count'],
                'missing': stats['missing'],
                'missing_pct': (stats['missing'] / results['total_rows']) * 100,
                'min': stats['min'],
                'max': stats['max'],
                'mean': stats['sum'] / stats['count'],
                'std': np.sqrt((stats['sum_sq'] / stats['count']) -
                              (stats['sum'] / stats['count'])**2)
            }
            numeric_summary[col] = col_summary

        final_results['numeric_summary'] = pd.DataFrame(numeric_summary).T

        # Process categorical summaries
        cat_summary = {}
        for col, counts in results['categorical_counts'].items():
            if not counts:
                continue

            # Convert to DataFrame
            cat_df = pd.DataFrame({
                'value': list(counts.keys()),
                'count': list(counts.values()),
            })
            cat_df['percentage'] = (cat_df['count'] / results['total_rows']) * 100
            cat_df = cat_df.sort_values('count', ascending=False)
            cat_summary[col] = cat_df

        final_results['categorical_summary'] = cat_summary

        # Process missing data
        missing_df = pd.DataFrame({
            'column': list(results['missing_counts'].keys()),
            'missing_count': list(results['missing_counts'].values()),
        })
        missing_df['missing_percentage'] = (missing_df['missing_count'] / results['total_rows']) * 100
        missing_df = missing_df.sort_values('missing_percentage', ascending=False)
        final_results['missing_data'] = missing_df

        return final_results

    def _export_streaming_results(self, results: Dict[str, Any], output_file: str) -> None:
        """Export streaming analysis results to Excel."""
        with pd.ExcelWriter(output_file) as writer:
            # Overall info
            pd.DataFrame({
                'Metric': ['Total Rows', 'CSV Chunks Processed'],
                'Value': [results['total_rows'], len(self.chunk_files)]
            }).to_excel(writer, sheet_name='Info', index=False)

            # Numeric summary
            results['numeric_summary'].to_excel(writer, sheet_name='Numeric_Summary')

            # Missing data
            results['missing_data'].to_excel(writer, sheet_name='Missing_Data', index=False)

            # Categorical summaries (top values only)
            for i, (col, df) in enumerate(results['categorical_summary'].items()):
                # Limit to top 1000 values to avoid Excel limitations
                df_limited = df.head(1000)

                # Sanitize sheet name
                sheet_name = f"Cat_{i+1}_{col[:10]}"
                sheet_name = sheet_name.replace(':', '_').replace('\\', '_').replace('/', '_') \
                                    .replace('?', '_').replace('*', '_').replace('[', '_') \
                                    .replace(']', '_')

                df_limited.to_excel(writer, sheet_name=sheet_name, index=False)

        print(f"Streaming analysis results saved to Excel: {output_file}")

    def _export_streaming_results_csv(self, results: Dict[str, Any], output_dir: str) -> None:
        """Export streaming analysis results to CSV files."""
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Overall info
        info_file = os.path.join(output_dir, 'info.csv')
        pd.DataFrame({
            'Metric': ['Total Rows', 'CSV Chunks Processed'],
            'Value': [results['total_rows'], len(self.chunk_files)]
        }).to_csv(info_file, index=False)

        # Numeric summary
        numeric_file = os.path.join(output_dir, 'numeric_summary.csv')
        results['numeric_summary'].to_csv(numeric_file)

        # Missing data
        missing_file = os.path.join(output_dir, 'missing_data.csv')
        results['missing_data'].to_csv(missing_file, index=False)

        # Categorical summaries
        cat_dir = os.path.join(output_dir, 'categorical')
        os.makedirs(cat_dir, exist_ok=True)

        for col, df in results['categorical_summary'].items():
            # Sanitize filename
            safe_col_name = col.replace(':', '_').replace('\\', '_').replace('/', '_') \
                              .replace('?', '_').replace('*', '_').replace('[', '_') \
                              .replace(']', '_')
            cat_file = os.path.join(cat_dir, f"{safe_col_name}.csv")
            df.to_csv(cat_file, index=False)

        print(f"Streaming analysis results saved to CSV directory: {output_dir}")


def batch_analyze_directory(
    chunk_dir: str,
    output_dir: Optional[str] = None,
    max_chunks: Optional[int] = None,
    streaming_mode: bool = True,
    columns_to_analyze: Optional[List[str]] = None,
    output_format: str = "excel",
    auto_split: bool = True,
    split_threshold: int = MAX_ROWS_PER_FILE
) -> str:
    """
    Analyze multiple CSV files in a directory in batch mode.

    Args:
        chunk_dir: Directory containing CSV chunk files
        output_dir: Directory to save output files (defaults to chunk_dir/batch_analysis)
        max_chunks: Maximum number of chunks to process (None for all)
        streaming_mode: Whether to use streaming mode for full-dataset analysis
        columns_to_analyze: Specific columns to analyze in streaming mode
        output_format: Format for output - 'excel', 'csv', or 'both'
        auto_split: Whether to automatically split large CSV files (default: True)
        split_threshold: Row count threshold for splitting files (default: 500,000)

    Returns:
        Path to the output directory
    """
    processor = BatchProcessor(
        chunk_dir,
        output_dir,
        output_format,
        auto_split=auto_split,
        split_threshold=split_threshold
    )

    if streaming_mode:
        # Process all chunks in streaming mode (better for truly huge datasets)
        results = processor.process_in_streaming_mode(columns_to_analyze)
        output_files = results.get('output_files', {})
        for fmt, path in output_files.items():
            print(f"Streaming analysis complete. {fmt.upper()} results saved to: {path}")
    else:
        # Process each chunk separately and then aggregate
        chunk_results = processor.analyze_chunks(max_chunks)
        print(f"Individual chunk analysis complete for {len(chunk_results)} chunks")

        # Aggregate results
        aggregated = processor.aggregate_statistics(max_chunks)
        print(f"Aggregated analysis complete for {aggregated['total_rows']} total rows")

    return processor.output_dir