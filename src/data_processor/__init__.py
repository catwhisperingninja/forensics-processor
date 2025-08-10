"""
Data processor package for Excel and CSV data processing, visualization, and analysis.
"""

from data_processor.excel_utils import ExcelFormatter, create_summary_report
from data_processor.visualizer import ExcelChartCreator, DataVisualizer, embed_images_in_excel
from data_processor.analyzer import DataAnalyzer, analyze_file
from data_processor.batch_processor import BatchProcessor, batch_analyze_directory
from data_processor.post_processor import post_process_batch_results
from data_processor.csv_splitter import split_csv, check_csv_row_counts, count_csv_rows

__all__ = [
    'ExcelFormatter',
    'create_summary_report',
    'ExcelChartCreator',
    'DataVisualizer',
    'embed_images_in_excel',
    'DataAnalyzer',
    'analyze_file',
    'BatchProcessor',
    'batch_analyze_directory',
    'post_process_batch_results',
    'split_csv',
    'check_csv_row_counts',
    'count_csv_rows'
]
