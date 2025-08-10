"""
Main module with examples for Excel data processing, visualization, and analysis.
"""
import os
import pandas as pd
import argparse
from typing import List, Dict, Optional

from data_processor.excel_utils import ExcelFormatter, create_summary_report
from data_processor.visualizer import ExcelChartCreator, DataVisualizer, embed_images_in_excel
from data_processor.analyzer import DataAnalyzer, analyze_file


def create_sample_data(output_path: str, rows: int = 100) -> str:
    """Create sample data for demonstration purposes."""
    import numpy as np
    from datetime import datetime, timedelta

    # Create sample data
    np.random.seed(42)

    # Date range
    start_date = datetime(2023, 1, 1)
    dates = [start_date + timedelta(days=i) for i in range(rows)]

    # Product categories
    categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Food']

    # Regions
    regions = ['North', 'South', 'East', 'West', 'Central']

    # Create DataFrame
    df = pd.DataFrame({
        'Date': dates,
        'Product': [np.random.choice(categories) for _ in range(rows)],
        'Region': [np.random.choice(regions) for _ in range(rows)],
        'Sales': np.random.normal(1000, 200, rows).round(2),
        'Quantity': np.random.randint(1, 50, rows),
        'Price': np.random.normal(100, 30, rows).round(2),
        'Discount': np.random.choice([0, 5, 10, 15, 20], rows),
        'Customer_Rating': np.random.randint(1, 6, rows),
    })

    # Add some missing values
    mask = np.random.random(rows) < 0.05
    df.loc[mask, 'Sales'] = np.nan

    # Add some outliers
    outlier_idx = np.random.choice(range(rows), 3, replace=False)
    df.loc[outlier_idx, 'Sales'] = df['Sales'].max() * 3

    # Save to CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    return output_path


def format_excel_report(input_csv: str, output_excel: str) -> str:
    """
    Create a formatted Excel report from a CSV file.

    Args:
        input_csv: Path to input CSV file
        output_excel: Path to output Excel file

    Returns:
        Path to the created Excel file
    """
    print(f"Creating formatted Excel report from {input_csv}...")

    # Load data
    df = pd.read_csv(input_csv)

    # Create formatter
    formatter = ExcelFormatter(output_excel)

    # Create data sheet
    formatter.df_to_excel_table(
        df=df,
        sheet_name='Data',
        table_name='SalesData',
        start_cell='A1'
    )

    # Format headers
    formatter.apply_header_style(
        sheet_name='Data',
        header_range='A1:H1'
    )

    # Apply conditional formatting for Sales column
    sales_col_idx = df.columns.get_loc('Sales') + 1
    sales_col_letter = chr(ord('A') + sales_col_idx)

    formatter.apply_conditional_formatting(
        sheet_name='Data',
        cell_range=f'{sales_col_letter}2:{sales_col_letter}{len(df)+1}',
        rule_type='color_scale'
    )

    # Apply conditional formatting for high customer ratings
    rating_col_idx = df.columns.get_loc('Customer_Rating') + 1
    rating_col_letter = chr(ord('A') + rating_col_idx)

    formatter.apply_conditional_formatting(
        sheet_name='Data',
        cell_range=f'{rating_col_letter}2:{rating_col_letter}{len(df)+1}',
        rule_type='cell_is',
        min_val=4,
        max_val=5,
        colors=['63BE7B']  # Green
    )

    # Autofit columns
    formatter.autofit_columns('Data')

    # Create summary sheet with pivot table
    pivot_df = pd.pivot_table(
        df,
        index='Product',
        columns='Region',
        values='Sales',
        aggfunc='sum'
    ).reset_index()

    formatter.df_to_excel_table(
        df=pivot_df,
        sheet_name='Summary',
        table_name='SalesSummary',
        start_cell='A1'
    )

    formatter.apply_header_style(
        sheet_name='Summary',
        header_range='A1:F1'
    )

    formatter.autofit_columns('Summary')

    formatter.save()
    formatter.close()

    print(f"Excel report created: {output_excel}")
    return output_excel


def add_visualizations(excel_file: str) -> List[str]:
    """
    Add visualizations to an Excel file.

    Args:
        excel_file: Path to Excel file

    Returns:
        List of paths to generated image files
    """
    print(f"Adding visualizations to {excel_file}...")

    # Check if we can read data from the Excel file
    try:
        # Try to read from the Data sheet
        df = pd.read_excel(excel_file, sheet_name='Data')
    except ValueError:
        # If Data sheet doesn't exist, try the first sheet
        try:
            available_sheets = pd.ExcelFile(excel_file).sheet_names
            if available_sheets:
                df = pd.read_excel(excel_file, sheet_name=available_sheets[0])
                print(f"Using sheet '{available_sheets[0]}' for data")
            else:
                # If no sheets are available, create a sample dataset
                print("No data sheets found. Creating sample data for visualizations.")
                np.random.seed(42)
                df = pd.DataFrame({
                    'Date': pd.date_range(start='2023-01-01', periods=30),
                    'Sales': np.random.normal(1000, 200, 30).round(2),
                    'Quantity': np.random.randint(1, 50, 30),
                    'Region': np.random.choice(['North', 'South', 'East', 'West', 'Central'], 30),
                    'Product': np.random.choice(['Electronics', 'Clothing', 'Furniture', 'Books', 'Food'], 30)
                })
        except Exception as e:
            print(f"Error reading Excel file: {e}")
            raise

    # Create charts in Excel
    chart_creator = ExcelChartCreator(excel_file)

    # Create Charts sheet if it doesn't exist
    if 'Charts' not in chart_creator.workbook.sheetnames:
        chart_creator.workbook.create_sheet('Charts')
        chart_creator.workbook.save(excel_file)

    # Add sales by region bar chart
    print("Adding bar chart...")
    region_sales = df.groupby('Region')['Sales'].sum().reset_index()
    region_sales.to_excel(excel_file, sheet_name='Charts', startrow=1, startcol=1, index=False)

    chart_creator.add_bar_chart(
        sheet_name='Charts',
        data_range='C3:C7',
        categories_range='B3:B7',
        title='Sales by Region',
        position='E2',
        width=12,
        height=8
    )

    # Add sales by product pie chart
    print("Adding pie chart...")
    product_sales = df.groupby('Product')['Sales'].sum().reset_index()
    product_sales.to_excel(excel_file, sheet_name='Charts', startrow=1, startcol=6, index=False)

    chart_creator.add_pie_chart(
        sheet_name='Charts',
        data_range='H3:H7',
        categories_range='G3:G7',
        title='Sales by Product',
        position='E12',
        width=12,
        height=8
    )

    # Add sales over time line chart
    print("Adding line chart...")
    time_sales = df.groupby('Date')['Sales'].sum().reset_index()
    time_sales.to_excel(excel_file, sheet_name='Charts', startrow=20, startcol=1, index=False)

    last_row = 20 + len(time_sales)
    chart_creator.add_line_chart(
        sheet_name='Charts',
        data_range=f'C21:C{last_row}',
        categories_range=f'B21:B{last_row}',
        title='Sales Over Time',
        position='E22',
        width=15,
        height=10
    )

    chart_creator.save()
    chart_creator.close()

    # Create external visualizations using matplotlib/seaborn
    print("Creating advanced visualizations...")
    output_dir = os.path.join(os.path.dirname(excel_file), 'images')
    os.makedirs(output_dir, exist_ok=True)
    visualizer = DataVisualizer(save_dir=output_dir)

    # Create time series plot
    time_series_path = visualizer.create_time_series_plot(
        df=df,
        date_col='Date',
        value_cols=['Sales', 'Quantity'],
        title='Sales and Quantity Over Time',
        figsize=(12, 6),
        save_as='time_series.png'
    )

    # Create correlation heatmap
    correlation_path = visualizer.create_correlation_heatmap(
        df=df,
        numeric_cols=['Sales', 'Quantity'],
        title='Correlation between Variables',
        figsize=(10, 8),
        save_as='correlation.png'
    )

    # Create distribution plots
    distributions_path = visualizer.create_distribution_plots(
        df=df,
        numeric_cols=['Sales', 'Quantity'],
        title='Distributions of Key Metrics',
        figsize=(12, 10),
        save_as='distributions.png'
    )

    # Create box plots
    boxplots_path = visualizer.create_box_plots(
        df=df,
        numeric_cols=['Sales'],
        category_col='Product',
        title='Sales Distribution by Product',
        figsize=(12, 6),
        save_as='boxplots.png'
    )

    # Embed images in Excel
    print("Embedding images in Excel...")
    image_paths = [
        time_series_path,
        correlation_path,
        distributions_path,
        boxplots_path
    ]

    embed_images_in_excel(excel_file, image_paths)

    print(f"Visualizations added to {excel_file}")
    return image_paths


def perform_analysis(excel_file: str) -> str:
    """
    Perform data analysis on an Excel file.

    Args:
        excel_file: Path to Excel file

    Returns:
        Path to analysis output file
    """
    print(f"Performing analysis on {excel_file}...")

    # Define output directory
    output_dir = os.path.join(os.path.dirname(excel_file), 'analysis')

    # Perform analysis
    results = analyze_file(excel_file, output_dir)

    print(f"Analysis completed. Results saved to: {results['output_file']}")
    return results['output_file']


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description='Excel Data Processor')
    parser.add_argument('--input', help='Input CSV or Excel file')
    parser.add_argument('--output', help='Output directory')
    parser.add_argument('--sample', action='store_true', help='Create sample data')
    parser.add_argument('--format', action='store_true', help='Format Excel report')
    parser.add_argument('--visualize', action='store_true', help='Add visualizations')
    parser.add_argument('--analyze', action='store_true', help='Perform data analysis')
    parser.add_argument('--all', action='store_true', help='Perform all operations')

    args = parser.parse_args()

    # Default paths
    default_output_dir = os.path.join(os.getcwd(), 'data', 'output')
    os.makedirs(default_output_dir, exist_ok=True)

    input_path = args.input
    output_dir = args.output or default_output_dir

    # Create sample data if requested or if no input file provided
    if args.sample or args.all or not input_path:
        sample_path = os.path.join(output_dir, 'sample_data.csv')
        input_path = create_sample_data(sample_path)
        print(f"Sample data created: {input_path}")

    # Format Excel report
    excel_path = None
    if args.format or args.all:
        if input_path.endswith('.csv'):
            excel_path = os.path.join(output_dir, 'formatted_report.xlsx')
            excel_path = format_excel_report(input_path, excel_path)
        else:
            excel_path = input_path
            print(f"Using existing Excel file: {excel_path}")
    else:
        excel_path = input_path

    # Add visualizations
    if args.visualize or args.all:
        if excel_path.endswith('.xlsx') or excel_path.endswith('.xls'):
            add_visualizations(excel_path)
        else:
            print("Skipping visualizations: Input file must be an Excel file")

    # Perform analysis
    if args.analyze or args.all:
        perform_analysis(excel_path if excel_path else input_path)

    print("Processing completed.")


if __name__ == "__main__":
    main()
