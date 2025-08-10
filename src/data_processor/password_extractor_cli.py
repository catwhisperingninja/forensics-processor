#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLI tool for the Password Extractor module
Provides a command-line interface to extract credentials from browser forensic data
"""

import os
import sys
import re
import logging
import argparse
from datetime import datetime
from pathlib import Path

from src.data_processor.password_extractor import PasswordExtractor


def setup_logging(verbose: bool) -> logging.Logger:
    """Configure logging for the CLI."""
    log_level = logging.DEBUG if verbose else logging.INFO

    # Create logger
    logger = logging.getLogger('password_extractor_cli')
    logger.setLevel(log_level)

    # Create console handler and set level
    ch = logging.StreamHandler()
    ch.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Add formatter to ch
    ch.setFormatter(formatter)

    # Add ch to logger
    logger.addHandler(ch)

    return logger


def validate_directory(dir_path: str, should_exist: bool = True) -> str:
    """
    Validate that a directory exists or can be created.

    Args:
        dir_path: Directory path to validate
        should_exist: Whether the directory should already exist

    Returns:
        Validated directory path

    Raises:
        argparse.ArgumentTypeError: If validation fails
    """
    path = Path(dir_path)

    if should_exist and not path.exists():
        raise argparse.ArgumentTypeError(f"Directory does not exist: {dir_path}")

    if should_exist and not path.is_dir():
        raise argparse.ArgumentTypeError(f"Path is not a directory: {dir_path}")

    return dir_path


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Extract potential plaintext passwords and credentials from browser forensic data',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--input-dir', '-i', required=True,
                        type=lambda x: validate_directory(x, True),
                        help='Directory containing browser forensic data or previously processed analysis')

    parser.add_argument('--output-dir', '-o',
                        default=f'./password_extraction_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                        help='Directory where extraction results will be saved')

    parser.add_argument('--max-files', '-m', type=int, default=0,
                        help='Maximum number of files to process (0 = all files)')

    parser.add_argument('--ctf-focus', '-c', action='store_true',
                        help='Focus on finding CTF flags with common formats')

    parser.add_argument('--base64-decode', '-b', action='store_true',
                        help='Attempt to decode base64 strings and check for credentials')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')

    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress non-essential output')

    parser.add_argument('--raw-files', '-r', action='store_true',
                        help='Process raw CSV files directly, even if processed data is available')

    return parser.parse_args()


def main():
    """Run the password extractor from the command line."""
    # Parse arguments
    args = parse_arguments()

    # Set up logging
    logger = setup_logging(args.verbose)

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        # Create output directory
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Password Extractor")
        logger.info("=================")
        logger.info(f"Input directory: {args.input_dir}")
        logger.info(f"Output directory: {args.output_dir}")

        # Create and run extractor
        extractor = PasswordExtractor(args.input_dir, args.output_dir)

        # Add CTF-specific patterns if requested
        if args.ctf_focus:
            logger.info("Adding CTF-specific flag patterns...")
            extractor.ctf_flag_patterns.extend([
                # Add more CTF-specific patterns
                re.compile(r'ctf\d{4}:\s*[a-zA-Z0-9_-]+', re.IGNORECASE),
                re.compile(r'flag\d{0,4}:\s*[a-zA-Z0-9_-]+', re.IGNORECASE),
                re.compile(r'key\d{0,4}:\s*[a-zA-Z0-9_-]+', re.IGNORECASE),
                re.compile(r'secret\d{0,4}:\s*[a-zA-Z0-9_-]+', re.IGNORECASE),
                # Common formats with underscores
                re.compile(r'CTF_[a-zA-Z0-9_-]+', re.IGNORECASE),
                re.compile(r'FLAG_[a-zA-Z0-9_-]+', re.IGNORECASE),
                re.compile(r'KEY_[a-zA-Z0-9_-]+', re.IGNORECASE),
                # Hex-based formats
                re.compile(r'(CTF|FLAG|KEY)[a-f0-9]{16,64}', re.IGNORECASE),
                # Additional CTF flag formats
                re.compile(r'flag\{[^}]{8,64}\}', re.IGNORECASE),
                re.compile(r'key\{[^}]{8,64}\}', re.IGNORECASE),
                re.compile(r'ctf\{[^}]{8,64}\}', re.IGNORECASE),
                re.compile(r'secret\{[^}]{8,64}\}', re.IGNORECASE),
                re.compile(r'password\{[^}]{8,64}\}', re.IGNORECASE)
            ])

        # Run extraction
        if args.raw_files:
            logger.info("Processing raw CSV files directly...")
            csv_files = extractor.scan_csv_files(args.max_files)
            results = extractor.extract_from_raw_data(csv_files)
            output_files = extractor.export_results(results)
        else:
            output_files = extractor.run_extraction(args.max_files)

        # Print results
        logger.info("\nExtraction Results:")
        logger.info("-------------------")
        for file_type, file_path in output_files.items():
            logger.info(f"{file_type.capitalize()}: {file_path}")

        logger.info(f"\nSummary report available at: {output_files.get('summary', 'N/A')}")

        # Create a simple text file with direct paths to results
        with open(output_dir / 'extraction_paths.txt', 'w') as f:
            f.write("# Password Extraction Results\n\n")
            for file_type, file_path in output_files.items():
                f.write(f"{file_type.capitalize()}: {file_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            logger.debug(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())