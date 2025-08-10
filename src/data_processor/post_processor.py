"""
Post-Processing module for creating visualizations from batch processing outputs.
"""
import os
import argparse
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime

from data_processor.visualizer import DataVisualizer, ExcelChartCreator, embed_images_in_excel
from data_processor.excel_utils import ExcelFormatter


def load_batch_results(csv_dir: str) -> Dict[str, pd.DataFrame]:
    """
    Load batch processing results from CSV directory.

    Args:
        csv_dir: Directory containing CSV outputs from batch processing

    Returns:
        Dictionary of DataFrames with loaded data
    """
    results = {}

    # Load general info
    info_path = os.path.join(csv_dir, 'info.csv')
    if os.path.exists(info_path):
        results['info'] = pd.read_csv(info_path)

    # Load missing data
    missing_path = os.path.join(csv_dir, 'missing_data.csv')
    if os.path.exists(missing_path):
        results['missing_data'] = pd.read_csv(missing_path)

    # Load numeric summary
    numeric_path = os.path.join(csv_dir, 'numeric_summary.csv')
    if os.path.exists(numeric_path):
        results['numeric_summary'] = pd.read_csv(numeric_path)

    # Load categorical data
    cat_dir = os.path.join(csv_dir, 'categorical')
    if os.path.exists(cat_dir):
        results['categorical'] = {}
        for file in os.listdir(cat_dir):
            if file.endswith('.csv'):
                cat_name = os.path.splitext(file)[0]
                cat_path = os.path.join(cat_dir, file)
                results['categorical'][cat_name] = pd.read_csv(cat_path)

    return results


def create_visualizations(batch_results: Dict[str, Any], output_dir: str) -> str:
    """
    Create visualizations from batch processing results.

    Args:
        batch_results: Dictionary with loaded batch processing results
        output_dir: Directory to save visualization outputs

    Returns:
        Path to the Excel file with visualizations
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Create Excel file for visualizations
    excel_path = os.path.join(output_dir, f'batch_visualizations_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx')

    # Initialize Excel formatter
    formatter = ExcelFormatter(excel_path)

    # Add summary info to Excel
    if 'info' in batch_results:
        formatter.df_to_excel_table(
            df=batch_results['info'],
            sheet_name='Summary',
            table_name='BatchInfo',
            start_cell='A1'
        )
        formatter.apply_header_style(
            sheet_name='Summary',
            header_range='A1:B1'
        )

    # Add missing data analysis
    if 'missing_data' in batch_results:
        missing_df = batch_results['missing_data']

        # Add to Excel
        formatter.df_to_excel_table(
            df=missing_df,
            sheet_name='Missing_Data',
            table_name='MissingData',
            start_cell='A1'
        )
        formatter.apply_header_style(
            sheet_name='Missing_Data',
            header_range='A1:C1'
        )

        # Apply conditional formatting for percentage column
        formatter.apply_conditional_formatting(
            sheet_name='Missing_Data',
            cell_range=f'C2:C{len(missing_df)+1}',
            rule_type='color_scale'
        )

    # Save initial Excel file
    formatter.save()
    formatter.close()

    # Create charts
    create_excel_charts(batch_results, excel_path)

    # Create advanced visualizations
    image_paths = create_advanced_visualizations(batch_results, output_dir)

    # Embed generated images in Excel
    if image_paths:
        embed_images_in_excel(excel_path, image_paths)

    print(f"Visualization complete. Results saved to: {excel_path}")
    return excel_path


def create_excel_charts(batch_results: Dict[str, Any], excel_path: str) -> None:
    """
    Create Excel charts from batch processing results.

    Args:
        batch_results: Dictionary with loaded batch processing results
        excel_path: Path to Excel file to add charts to
    """
    chart_creator = ExcelChartCreator(excel_path)

    # Check if we have categorical data to visualize
    if 'categorical' in batch_results and batch_results['categorical']:
        # Create Charts sheet if it doesn't exist
        if 'Charts' not in chart_creator.workbook.sheetnames:
            chart_creator.workbook.create_sheet('Charts')
            chart_creator.workbook.save(excel_path)

        # Find top categories to chart (limit to 5 for readability)
        top_categories = []
        for category, df in batch_results['categorical'].items():
            if len(df) > 1:  # Only include categories with multiple values
                top_categories.append((category, df))
                if len(top_categories) >= 5:
                    break

        # Add charts for each category
        for i, (category, df) in enumerate(top_categories):
            # Prepare data for chart (limit to top 10 values)
            chart_df = df.head(10).copy()

            # Add to Excel
            start_row = i * 15 + 1
            chart_df.to_excel(excel_path, sheet_name='Charts', startrow=start_row, startcol=1, index=False)

            # Calculate data range
            last_row = start_row + len(chart_df)

            # Add bar chart
            chart_creator.add_bar_chart(
                sheet_name='Charts',
                data_range=f'D{start_row+2}:D{last_row+1}', # Count column
                categories_range=f'B{start_row+2}:B{last_row+1}', # Value column
                title=f'Top {category} Distribution',
                position=f'F{start_row+1}',
                width=12,
                height=8
            )

            # Add pie chart for top 5 only (if we have enough data)
            if len(chart_df) >= 5:
                pie_df = chart_df.head(5)
                pie_row = start_row + len(chart_df) + 2
                pie_df.to_excel(excel_path, sheet_name='Charts', startrow=pie_row, startcol=1, index=False)

                last_pie_row = pie_row + len(pie_df)
                chart_creator.add_pie_chart(
                    sheet_name='Charts',
                    data_range=f'D{pie_row+2}:D{last_pie_row+1}',
                    categories_range=f'B{pie_row+2}:B{last_pie_row+1}',
                    title=f'Top 5 {category} (Pie)',
                    position=f'F{pie_row+1}',
                    width=10,
                    height=8
                )

    chart_creator.save()
    chart_creator.close()


def create_advanced_visualizations(batch_results: Dict[str, Any], output_dir: str) -> List[str]:
    """
    Create advanced matplotlib/seaborn visualizations from batch results.

    Args:
        batch_results: Dictionary with loaded batch processing results
        output_dir: Directory to save visualization outputs

    Returns:
        List of paths to generated image files
    """
    # Create images directory
    images_dir = os.path.join(output_dir, 'images')
    os.makedirs(images_dir, exist_ok=True)

    # Initialize visualizer
    visualizer = DataVisualizer(save_dir=images_dir)

    image_paths = []

    # Create missing data visualization if available
    if 'missing_data' in batch_results:
        missing_df = batch_results['missing_data']

        # Filter to only show columns with missing data
        missing_with_data = missing_df[missing_df['missing_percentage'] > 0].sort_values('missing_percentage', ascending=False)

        if not missing_with_data.empty:
            # Create plot
            try:
                import matplotlib.pyplot as plt
                import seaborn as sns

                plt.figure(figsize=(12, 6))
                sns.barplot(x='column', y='missing_percentage', data=missing_with_data.head(15))
                plt.title('Missing Data by Column (%)')
                plt.xticks(rotation=45, ha='right')
                plt.grid(axis='y', alpha=0.3)
                plt.tight_layout()

                # Save plot
                missing_path = os.path.join(images_dir, 'missing_data.png')
                plt.savefig(missing_path, dpi=300)
                plt.close()

                image_paths.append(missing_path)
            except Exception as e:
                print(f"Error creating missing data visualization: {str(e)}")

    # Create categorical visualizations (top distributions)
    if 'categorical' in batch_results and batch_results['categorical']:
        # Limit to top 3 categories for visualization
        top_categories = list(batch_results['categorical'].items())[:3]

        for category, df in top_categories:
            try:
                # Only visualize if enough data points
                if len(df) >= 5:
                    plt.figure(figsize=(12, 6))

                    # Plot top 15 values
                    top_df = df.head(15).copy()
                    sns.barplot(x='value', y='percentage', data=top_df)
                    plt.title(f'{category} Distribution (%)')
                    plt.xticks(rotation=45, ha='right')
                    plt.grid(axis='y', alpha=0.3)
                    plt.tight_layout()

                    # Save plot
                    cat_path = os.path.join(images_dir, f'{category}_distribution.png')
                    plt.savefig(cat_path, dpi=300)
                    plt.close()

                    image_paths.append(cat_path)
            except Exception as e:
                print(f"Error creating visualization for {category}: {str(e)}")

    return image_paths


def post_process_batch_results(csv_dir: str, output_dir: Optional[str] = None) -> str:
    """
    Main function to post-process batch results and create visualizations.

    Args:
        csv_dir: Directory containing CSV outputs from batch processing
        output_dir: Directory to save visualization outputs (default: next to csv_dir)

    Returns:
        Path to the Excel file with visualizations
    """
    # Validate input directory
    if not os.path.exists(csv_dir):
        raise ValueError(f"CSV directory not found: {csv_dir}")

    # Set default output directory if not specified
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(csv_dir), 'visualizations')

    # Load batch results
    print(f"Loading batch results from: {csv_dir}")
    batch_results = load_batch_results(csv_dir)

    # Check if we have data to process
    if not batch_results:
        raise ValueError("No batch processing results found in the specified directory")

    # Create visualizations
    print("Creating visualizations...")
    excel_path = create_visualizations(batch_results, output_dir)

    return excel_path


def main():
    """CLI entry point for post-processing batch results."""
    parser = argparse.ArgumentParser(description='Post-process batch results to create visualizations')

    parser.add_argument('--input-dir', required=True,
                        help='Directory containing CSV outputs from batch processing')

    parser.add_argument('--output-dir',
                        help='Directory to save visualization outputs (default: next to input directory)')

    args = parser.parse_args()

    try:
        excel_path = post_process_batch_results(args.input_dir, args.output_dir)
        print(f"Post-processing complete! Visualizations saved to: {excel_path}")
        return 0
    except Exception as e:
        print(f"Error during post-processing: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())