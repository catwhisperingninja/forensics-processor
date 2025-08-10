#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command Line Interface for Browser Credential & Autofill Security Risk Analysis
"""

import os
import sys
import argparse
from pathlib import Path
import logging
from datetime import datetime

# Add parent directory to path to allow importing from this project
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from data_processor.credential_risk_analyzer import CredentialRiskAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Browser Credential & Autofill Security Risk Analysis Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--analysis-dir', '-a', required=True,
                       help='Directory containing credential analysis results')

    parser.add_argument('--output-dir', '-o',
                       help='Directory where risk analysis results will be saved (defaults to analysis_dir/risk_analysis)')

    parser.add_argument('--report-format', '-r', choices=['md', 'json', 'all'],
                       default='all', help='Format for output reports')

    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress progress information')

    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    parser.add_argument('--visualize', '-z', action='store_true',
                       help='Generate visualizations for domain network analysis')

    return parser.parse_args()


def setup_logging(args):
    """Configure logging based on command line arguments."""
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


def validate_analysis_directory(analysis_dir):
    """Validate that the analysis directory exists and contains credential analysis files."""
    analysis_path = Path(analysis_dir)

    if not analysis_path.exists():
        logger.error(f"Analysis directory does not exist: {analysis_dir}")
        return False

    if not analysis_path.is_dir():
        logger.error(f"Analysis path is not a directory: {analysis_dir}")
        return False

    # Check for required credential analysis files
    required_file_patterns = [
        "login_data_*.csv",
        "autofill_*.csv",
        "urls_*.csv"
    ]

    for pattern in required_file_patterns:
        files = list(analysis_path.glob(pattern))
        if not files:
            logger.warning(f"No files matching {pattern} found in analysis directory")

    # If we have at least one of these files, we can proceed
    all_files = []
    for pattern in required_file_patterns:
        all_files.extend(list(analysis_path.glob(pattern)))

    if not all_files:
        logger.error(f"No credential analysis files found in {analysis_dir}")
        logger.error("Run credential_analyzer.py first to generate analysis data")
        return False

    logger.info(f"Found credential analysis files in {analysis_dir}")
    return True


def print_risk_summary(results):
    """Print a summary of the risk analysis results to the console."""
    if not results or 'overall_risk' not in results:
        logger.warning("No risk analysis results to summarize")
        return

    overall_risk = results['overall_risk']
    risk_level = overall_risk.get('risk_level', 'unknown').upper()
    score = overall_risk.get('score', 0)

    print("\n" + "="*70)
    print(f"BROWSER SECURITY RISK ANALYSIS SUMMARY")
    print("="*70)

    # Use colors if available
    try:
        from colorama import init, Fore, Style
        init()

        if risk_level == 'HIGH':
            risk_color = Fore.RED
        elif risk_level == 'MEDIUM':
            risk_color = Fore.YELLOW
        else:
            risk_color = Fore.GREEN

        print(f"Overall Security Risk: {risk_color}{risk_level}{Style.RESET_ALL}")
        print(f"Risk Score: {risk_color}{score:.1f}/10{Style.RESET_ALL}")
    except ImportError:
        print(f"Overall Security Risk: {risk_level}")
        print(f"Risk Score: {score:.1f}/10")

    print("\nKey Risk Factors:")
    risk_factors = overall_risk.get('risk_factors', [])
    if risk_factors:
        for factor in risk_factors:
            print(f"- {factor}")
    else:
        print("- No significant risk factors identified")

    # Print each analysis area's risk level
    if 'analyses' in results:
        analyses = results['analyses']
        print("\nRisk Level by Analysis Area:")

        for area, data in analyses.items():
            area_name = area.replace('_', ' ').title()
            area_risk = data.get('risk_level', 'unknown').upper()

            try:
                if area_risk == 'HIGH':
                    print(f"- {area_name}: {Fore.RED}{area_risk}{Style.RESET_ALL}")
                elif area_risk == 'MEDIUM':
                    print(f"- {area_name}: {Fore.YELLOW}{area_risk}{Style.RESET_ALL}")
                else:
                    print(f"- {area_name}: {Fore.GREEN}{area_risk}{Style.RESET_ALL}")
            except NameError:
                print(f"- {area_name}: {area_risk}")

    # Print location of full report
    print("\nFor full details, see the generated security risk report.")
    print("="*70 + "\n")


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    setup_logging(args)

    logger.info("Browser Credential & Autofill Security Risk Analysis Tool")
    logger.info("======================================================")

    # Validate analysis directory
    if not validate_analysis_directory(args.analysis_dir):
        sys.exit(1)

    # Run risk analysis
    try:
        analyzer = CredentialRiskAnalyzer(args.analysis_dir, args.output_dir)
        results = analyzer.run_risk_analysis()

        # Print summary to console
        print_risk_summary(results)

        # Optional: Generate visualizations if requested
        if args.visualize:
            try:
                logger.info("Generating visualizations...")
                # Here we would add code to generate visualizations
                # This would typically use matplotlib, networkx, etc.
                # For now we'll just log that this feature is not implemented
                logger.info("Visualization feature is planned for a future release")
            except Exception as e:
                logger.error(f"Error generating visualizations: {str(e)}")

        logger.info("Security risk analysis complete!")

    except Exception as e:
        logger.error(f"Error during risk analysis: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()