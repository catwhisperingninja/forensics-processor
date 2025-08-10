#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command Line Interface for Browser Credential & Autofill Analysis
"""

import os
import sys
import argparse
from pathlib import Path
import logging
from datetime import datetime

# Add parent directory to path to allow importing from this project
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from data_processor.credential_analyzer import CredentialAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Browser Credential & Autofill Forensic Analysis Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--input-dir', '-i', required=True,
                       help='Directory containing browser forensic CSV files')

    parser.add_argument('--output-dir', '-o', default='./credential_analysis',
                       help='Directory where analysis results will be saved')

    parser.add_argument('--focused-mode', '-f', choices=['all', 'credentials', 'autofill', 'extensions', 'urls'],
                       default='all', help='Focus analysis on specific artifact types')

    parser.add_argument('--domain-filter', '-d',
                       help='Filter results to specific domains (comma-separated list)')

    parser.add_argument('--report-format', '-r', choices=['md', 'json', 'csv', 'all'],
                       default='all', help='Format for output reports')

    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress progress information')

    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    parser.add_argument('--max-files', '-m', type=int, default=0,
                       help='Maximum number of files to process (0 = all files)')

    return parser.parse_args()


def setup_logging(args):
    """Configure logging based on command line arguments."""
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


def validate_input_directory(input_dir):
    """Validate that the input directory exists and contains CSV files."""
    input_path = Path(input_dir)

    if not input_path.exists():
        logger.error(f"Input directory does not exist: {input_dir}")
        return False

    if not input_path.is_dir():
        logger.error(f"Input path is not a directory: {input_dir}")
        return False

    csv_files = list(input_path.glob("*.csv"))
    if not csv_files:
        logger.error(f"No CSV files found in input directory: {input_dir}")
        return False

    logger.info(f"Found {len(csv_files)} CSV files in {input_dir}")
    return True


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    setup_logging(args)

    logger.info("Browser Credential & Autofill Analysis Tool")
    logger.info("=========================================")

    # Validate input directory
    if not validate_input_directory(args.input_dir):
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Configure domain filter if provided
    domain_filters = None
    if args.domain_filter:
        domain_filters = [d.strip() for d in args.domain_filter.split(',')]
        logger.info(f"Filtering results to domains: {', '.join(domain_filters)}")

    # Create timestamped subdirectory for this run
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_path / f"run_{timestamp}"
    run_dir.mkdir(exist_ok=True)

    # Determine the mode of operation
    logger.info(f"Analysis mode: {args.focused_mode}")

    # Run the credential analyzer
    try:
        analyzer = CredentialAnalyzer(args.input_dir, str(run_dir))

        # Limit number of files if specified
        if args.max_files > 0:
            logger.info(f"Processing at most {args.max_files} files")
            csv_files, _ = analyzer.find_forensic_files()
            csv_files = csv_files[:args.max_files]
            artifacts = analyzer.scan_for_credential_artifacts(csv_files)
        else:
            # Run full analysis
            analyzer.run_analysis()
            logger.info(f"Analysis complete! Results saved to {run_dir}")
            return

        # If we limited the files, we need to complete the analysis
        url_analysis = analyzer.analyze_url_patterns(artifacts['urls'])
        analyzer.export_results(artifacts, url_analysis)
        logger.info(f"Analysis complete! Results saved to {run_dir}")

    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()