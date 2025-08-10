"""
Data Analysis module for analyzing Excel and CSV data.
"""
import os
from typing import List, Dict, Any, Tuple, Optional, Union
import pandas as pd
import numpy as np
from pandas.api.types import is_numeric_dtype


class DataAnalyzer:
    """Class for analyzing data from Excel and CSV files."""

    def __init__(self, file_path: str, sheet_name: Optional[str] = None):
        """
        Initialize analyzer with a data file.

        Args:
            file_path: Path to Excel or CSV file
            sheet_name: Specific sheet name to load (for Excel files)
        """
        self.file_path = file_path

        # Load data based on file extension
        if file_path.endswith('.csv'):
            self.data = pd.read_csv(file_path)
        elif file_path.endswith(('.xlsx', '.xls')):
            try:
                if sheet_name:
                    # Try to load the specified sheet
                    self.data = pd.read_excel(file_path, sheet_name=sheet_name)
                else:
                    # Try to load a standard sheet name
                    for std_sheet in ['Data', 'Sheet1', 'Sheet', 'data']:
                        try:
                            self.data = pd.read_excel(file_path, sheet_name=std_sheet)
                            print(f"Using sheet '{std_sheet}' for analysis")
                            break
                        except ValueError:
                            continue
                    else:
                        # If no standard sheet found, load the first sheet
                        xls = pd.ExcelFile(file_path)
                        if xls.sheet_names:
                            self.data = pd.read_excel(file_path, sheet_name=xls.sheet_names[0])
                            print(f"Using sheet '{xls.sheet_names[0]}' for analysis")
                        else:
                            # Create an empty DataFrame as fallback
                            self.data = pd.DataFrame()
                            print("No data found in Excel file. Using empty DataFrame.")
            except Exception as e:
                print(f"Error reading Excel file: {e}")
                # Create an empty DataFrame as fallback
                self.data = pd.DataFrame()
        else:
            raise ValueError(f"Unsupported file format: {file_path}")

        # Make a copy to avoid modifying original
        self.original_data = self.data.copy()

    def get_summary_stats(self, columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Get summary statistics for numeric columns.

        Args:
            columns: List of columns to analyze (None for all numeric)

        Returns:
            DataFrame with summary statistics
        """
        # Select columns
        df = self.data
        if columns:
            df = df[columns]

        # Get numeric columns only
        numeric_cols = df.select_dtypes(include=['number']).columns

        # Calculate statistics
        stats = df[numeric_cols].describe().T

        # Add additional statistics
        stats['missing'] = df[numeric_cols].isna().sum()
        stats['missing_pct'] = (df[numeric_cols].isna().sum() / len(df)) * 100
        stats['unique'] = df[numeric_cols].nunique()

        return stats

    def get_categorical_summary(self, columns: Optional[List[str]] = None) -> Dict[str, pd.DataFrame]:
        """
        Get summary for categorical columns.

        Args:
            columns: List of columns to analyze (None for all categorical)

        Returns:
            Dictionary of DataFrames with value counts for each categorical column
        """
        # Select columns
        df = self.data
        if columns:
            df = df[columns]

        # Get categorical columns
        cat_cols = df.select_dtypes(exclude=['number']).columns

        result = {}
        for col in cat_cols:
            # Get value counts and calculate percentages
            vc = df[col].value_counts(dropna=False).reset_index()
            vc.columns = [col, 'count']
            vc['percentage'] = (vc['count'] / len(df)) * 100

            # Sort by count (descending)
            vc = vc.sort_values('count', ascending=False)

            result[col] = vc

        return result

    def find_missing_data(self) -> pd.DataFrame:
        """
        Analyze missing data across all columns.

        Returns:
            DataFrame with missing data counts and percentages
        """
        # Calculate missing values
        missing = pd.DataFrame({
            'count': self.data.isna().sum(),
            'percentage': (self.data.isna().sum() / len(self.data)) * 100
        })

        # Sort by percentage (descending)
        missing = missing.sort_values('percentage', ascending=False)

        return missing

    def find_outliers(
        self,
        columns: Optional[List[str]] = None,
        method: str = 'iqr',
        threshold: float = 1.5
    ) -> Dict[str, pd.DataFrame]:
        """
        Find outliers in numeric columns.

        Args:
            columns: List of columns to analyze (None for all numeric)
            method: Method to detect outliers ('iqr' or 'zscore')
            threshold: Threshold for outlier detection (1.5 for IQR, 3 for z-score)

        Returns:
            Dictionary of DataFrames with outlier rows for each column
        """
        # Select columns
        df = self.data
        if columns:
            numeric_cols = [col for col in columns if is_numeric_dtype(df[col])]
        else:
            numeric_cols = df.select_dtypes(include=['number']).columns

        result = {}
        for col in numeric_cols:
            # Skip columns with all missing values
            if df[col].isna().all():
                continue

            if method == 'iqr':
                # IQR method
                Q1 = df[col].quantile(0.25)
                Q3 = df[col].quantile(0.75)
                IQR = Q3 - Q1

                lower_bound = Q1 - threshold * IQR
                upper_bound = Q3 + threshold * IQR

                # Find outliers
                outliers = df[(df[col] < lower_bound) | (df[col] > upper_bound)].copy()

                # Add bounds information
                outliers['lower_bound'] = lower_bound
                outliers['upper_bound'] = upper_bound

            elif method == 'zscore':
                # Z-score method
                mean = df[col].mean()
                std = df[col].std()

                # Calculate z-scores
                z_scores = (df[col] - mean) / std

                # Find outliers
                outliers = df[abs(z_scores) > threshold].copy()

                # Add z-score information
                outliers['z_score'] = z_scores[abs(z_scores) > threshold]

            else:
                raise ValueError(f"Unsupported method: {method}")

            if not outliers.empty:
                result[col] = outliers

        return result

    def create_pivot_table(
        self,
        index: Union[str, List[str]],
        values: Union[str, List[str]],
        columns: Optional[Union[str, List[str]]] = None,
        aggfunc: str = 'mean'
    ) -> pd.DataFrame:
        """
        Create a pivot table.

        Args:
            index: Column(s) to use as index
            values: Column(s) to aggregate
            columns: Column(s) to use as columns (optional)
            aggfunc: Aggregation function ('mean', 'sum', 'count', etc.)

        Returns:
            Pivot table as DataFrame
        """
        return pd.pivot_table(
            self.data,
            index=index,
            values=values,
            columns=columns,
            aggfunc=aggfunc
        )

    def analyze_correlation(self, columns: Optional[List[str]] = None, method: str = 'pearson') -> pd.DataFrame:
        """
        Analyze correlation between numeric columns.

        Args:
            columns: List of columns to analyze (None for all numeric)
            method: Correlation method ('pearson', 'spearman', or 'kendall')

        Returns:
            Correlation matrix
        """
        # Select columns
        df = self.data
        if columns:
            df = df[columns]

        # Get numeric columns only
        numeric_cols = df.select_dtypes(include=['number']).columns

        # Calculate correlation
        corr = df[numeric_cols].corr(method=method)

        return corr

    def find_duplicates(self, subset: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Find duplicate rows in the data.

        Args:
            subset: Columns to consider when detecting duplicates (None for all)

        Returns:
            DataFrame with duplicate rows
        """
        duplicates = self.data[self.data.duplicated(subset=subset, keep=False)]
        return duplicates.sort_values(by=subset if subset else self.data.columns[0])

    def group_and_aggregate(
        self,
        groupby_cols: List[str],
        agg_dict: Dict[str, List[str]]
    ) -> pd.DataFrame:
        """
        Group data and apply aggregations.

        Args:
            groupby_cols: Columns to group by
            agg_dict: Dictionary mapping columns to aggregation functions
                e.g., {'sales': ['sum', 'mean'], 'quantity': ['count']}

        Returns:
            Grouped and aggregated DataFrame
        """
        result = self.data.groupby(groupby_cols).agg(agg_dict)
        return result

    def analyze_time_series(
        self,
        date_col: str,
        value_cols: List[str],
        freq: str = 'M'
    ) -> pd.DataFrame:
        """
        Analyze time series data.

        Args:
            date_col: Column containing dates
            value_cols: Columns with values to analyze
            freq: Frequency for resampling ('D' for daily, 'W' for weekly, 'M' for monthly, etc.)

        Returns:
            DataFrame with time series analysis
        """
        # Ensure date column is datetime
        df = self.data.copy()
        df[date_col] = pd.to_datetime(df[date_col])

        # Set date as index
        df = df.set_index(date_col)

        # Select value columns
        df = df[value_cols]

        # Resample and calculate statistics
        result = df.resample(freq).agg(['mean', 'min', 'max', 'sum', 'count'])

        return result

    def detect_patterns(self, column: str, window: int = 3) -> pd.DataFrame:
        """
        Detect patterns in a time series column.

        Args:
            column: Column to analyze
            window: Window size for rolling statistics

        Returns:
            DataFrame with rolling statistics
        """
        # Select column
        series = self.data[column]

        # Calculate rolling statistics
        result = pd.DataFrame({
            'original': series,
            f'rolling_mean_{window}': series.rolling(window=window).mean(),
            f'rolling_std_{window}': series.rolling(window=window).std(),
            'pct_change': series.pct_change() * 100,
            'cumulative_sum': series.cumsum()
        })

        return result

    def export_to_excel(self, output_path: str) -> None:
        """
        Export data to Excel file.

        Args:
            output_path: Path to save Excel file
        """
        self.data.to_excel(output_path, index=False)


def analyze_file(
    file_path: str,
    output_dir: str = "analysis_output"
) -> Dict[str, Any]:
    """
    Perform comprehensive analysis on a data file and export results.

    Args:
        file_path: Path to Excel or CSV file
        output_dir: Directory to save output files

    Returns:
        Dictionary with analysis results and paths to output files
    """
    # Create output directory if needed
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create analyzer
    analyzer = DataAnalyzer(file_path)

    # Get file name for output files
    file_name = os.path.splitext(os.path.basename(file_path))[0]

    # Dictionary to store results
    results = {}

    # Check if we have data to analyze
    if analyzer.data.empty:
        print("No data available for analysis. Creating empty analysis file.")
        # Create a simple empty report
        with pd.ExcelWriter(os.path.join(output_dir, f"{file_name}_analysis.xlsx")) as writer:
            pd.DataFrame({'message': ['No data available for analysis']}).to_excel(
                writer, sheet_name='Info', index=False)

        results['output_file'] = os.path.join(output_dir, f"{file_name}_analysis.xlsx")
        return results

    # 1. Basic summary statistics
    results['summary_stats'] = analyzer.get_summary_stats()

    # 2. Categorical analysis
    results['categorical_summary'] = analyzer.get_categorical_summary()

    # 3. Missing data analysis
    results['missing_data'] = analyzer.find_missing_data()

    # 4. Outlier detection
    results['outliers'] = analyzer.find_outliers()

    # 5. Correlation analysis
    results['correlation'] = analyzer.analyze_correlation()

    # 6. Duplicate detection
    results['duplicates'] = analyzer.find_duplicates()

    # Export results to Excel
    with pd.ExcelWriter(os.path.join(output_dir, f"{file_name}_analysis.xlsx")) as writer:
        # Summary stats
        if not results['summary_stats'].empty:
            results['summary_stats'].to_excel(writer, sheet_name='Summary_Stats')
        else:
            pd.DataFrame({'message': ['No numeric data for summary statistics']}).to_excel(
                writer, sheet_name='Summary_Stats', index=False)

        # Categorical summaries
        if results['categorical_summary']:
            for i, (col, df) in enumerate(results['categorical_summary'].items()):
                # Sanitize sheet name to remove invalid Excel sheet characters
                sheet_name = f"Cat_{i+1}_{col[:10]}"
                # Replace invalid Excel sheet name characters
                sheet_name = sheet_name.replace(':', '_').replace('\\', '_').replace('/', '_') \
                                      .replace('?', '_').replace('*', '_').replace('[', '_') \
                                      .replace(']', '_')
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        else:
            pd.DataFrame({'message': ['No categorical data available']}).to_excel(
                writer, sheet_name='Categories', index=False)

        # Missing data
        results['missing_data'].to_excel(writer, sheet_name='Missing_Data')

        # Outliers
        if results['outliers']:
            for i, (col, df) in enumerate(results['outliers'].items()):
                # Sanitize sheet name to remove invalid Excel sheet characters
                sheet_name = f"Outliers_{i+1}_{col[:10]}"
                # Replace invalid Excel sheet name characters
                sheet_name = sheet_name.replace(':', '_').replace('\\', '_').replace('/', '_') \
                                      .replace('?', '_').replace('*', '_').replace('[', '_') \
                                      .replace(']', '_')
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        else:
            pd.DataFrame({'message': ['No outliers detected']}).to_excel(
                writer, sheet_name='Outliers', index=False)

        # Correlation
        if not results['correlation'].empty:
            results['correlation'].to_excel(writer, sheet_name='Correlation')
        else:
            pd.DataFrame({'message': ['Insufficient data for correlation analysis']}).to_excel(
                writer, sheet_name='Correlation', index=False)

        # Duplicates
        if not results['duplicates'].empty:
            results['duplicates'].to_excel(writer, sheet_name='Duplicates', index=False)
        else:
            pd.DataFrame({'message': ['No duplicate records found']}).to_excel(
                writer, sheet_name='Duplicates', index=False)

    # Store output path
    results['output_file'] = os.path.join(output_dir, f"{file_name}_analysis.xlsx")

    return results