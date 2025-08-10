#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Credential & Autofill Analyzer for Browser Forensics Data
This module extracts and analyzes credential-related data from browser forensic files.
"""

import os
import csv
import pandas as pd
import sqlite3
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set, Optional
import json
from datetime import datetime
import tempfile
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CredentialAnalyzer:
    """Extract and analyze credential, autofill, and extension data from browser forensics."""

    def __init__(self, csv_dir: str, output_dir: str):
        """
        Initialize the credential analyzer.

        Args:
            csv_dir: Directory containing CSV forensic data files
            output_dir: Directory where analysis results will be saved
        """
        self.csv_dir = Path(csv_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories for different types of data
        self.credentials_dir = self.output_dir / "credentials"
        self.autofill_dir = self.output_dir / "autofill"
        self.extensions_dir = self.output_dir / "extensions"

        self.credentials_dir.mkdir(exist_ok=True)
        self.autofill_dir.mkdir(exist_ok=True)
        self.extensions_dir.mkdir(exist_ok=True)

        # Patterns for identifying credential-related data
        self.patterns = {
            'login_data': re.compile(r'Login Data', re.IGNORECASE),
            'autofill': re.compile(r'Autofill', re.IGNORECASE),
            'password': re.compile(r'password', re.IGNORECASE),
            'extension': re.compile(r'Extension', re.IGNORECASE),
            'lastpass': re.compile(r'lastpass', re.IGNORECASE),
            'cookies': re.compile(r'cookies', re.IGNORECASE),
        }

        # Cache for collected data
        self.login_data_files = []
        self.autofill_files = []
        self.extension_files = []
        self.visited_urls = []

    def find_forensic_files(self) -> Tuple[List[Path], int]:
        """
        Find all CSV files in the specified directory.

        Returns:
            Tuple containing list of file paths and total count
        """
        csv_files = list(self.csv_dir.glob("*.csv"))
        return csv_files, len(csv_files)

    def scan_for_credential_artifacts(self, csv_files: List[Path]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan CSV files for credential-related artifacts.

        Args:
            csv_files: List of CSV file paths to scan

        Returns:
            Dictionary of artifact types and their data
        """
        artifacts = {
            'login_data': [],
            'autofill': [],
            'extensions': [],
            'urls': [],
            'cookies': []
        }

        total_files = len(csv_files)

        for i, file_path in enumerate(csv_files):
            logger.info(f"Processing file {i+1}/{total_files}: {file_path.name}")

            # Process file in chunks to handle large files
            chunk_size = 100000  # Adjust based on available memory

            try:
                for chunk in pd.read_csv(file_path, chunksize=chunk_size):
                    # Look for credential-related columns
                    if 'message' in chunk.columns and 'source' in chunk.columns:
                        # Extract Login Data references
                        login_mask = chunk['message'].astype(str).str.contains('Login Data', na=False, case=False)
                        login_data = chunk[login_mask]

                        if not login_data.empty:
                            for _, row in login_data.iterrows():
                                artifacts['login_data'].append({
                                    'timestamp': row.get('datetime', ''),
                                    'message': row.get('message', ''),
                                    'source': row.get('source', ''),
                                    'path': self._extract_file_path(row.get('message', ''))
                                })

                        # Extract Autofill references
                        autofill_mask = chunk['message'].astype(str).str.contains('Autofill', na=False, case=False)
                        autofill_data = chunk[autofill_mask]

                        if not autofill_data.empty:
                            for _, row in autofill_data.iterrows():
                                artifacts['autofill'].append({
                                    'timestamp': row.get('datetime', ''),
                                    'message': row.get('message', ''),
                                    'source': row.get('source', ''),
                                    'path': self._extract_file_path(row.get('message', ''))
                                })

                        # Extract Extension references
                        extension_mask = chunk['message'].astype(str).str.contains('Extension', na=False, case=False)
                        extension_data = chunk[extension_mask]

                        if not extension_data.empty:
                            for _, row in extension_data.iterrows():
                                artifacts['extensions'].append({
                                    'timestamp': row.get('datetime', ''),
                                    'message': row.get('message', ''),
                                    'source': row.get('source', ''),
                                    'path': self._extract_file_path(row.get('message', ''))
                                })

                        # Extract URL history
                        url_mask = (
                            chunk['message'].astype(str).str.contains('http', na=False, case=False) &
                            chunk['message'].astype(str).str.contains('Visit', na=False, case=False)
                        )
                        url_data = chunk[url_mask]

                        if not url_data.empty:
                            for _, row in url_data.iterrows():
                                artifacts['urls'].append({
                                    'timestamp': row.get('datetime', ''),
                                    'message': row.get('message', ''),
                                    'source': row.get('source', ''),
                                    'url': self._extract_url(row.get('message', '')),
                                    'visit_count': self._extract_visit_count(row.get('message', '')),
                                    'visit_type': self._extract_visit_type(row.get('message', ''))
                                })

                        # Extract Cookie information
                        cookie_mask = chunk['message'].astype(str).str.contains('cookies', na=False, case=False)
                        cookie_data = chunk[cookie_mask]

                        if not cookie_data.empty:
                            for _, row in cookie_data.iterrows():
                                artifacts['cookies'].append({
                                    'timestamp': row.get('datetime', ''),
                                    'message': row.get('message', ''),
                                    'source': row.get('source', ''),
                                    'path': self._extract_file_path(row.get('message', ''))
                                })

            except Exception as e:
                logger.error(f"Error processing file {file_path.name}: {str(e)}")

        return artifacts

    def _extract_file_path(self, message: str) -> str:
        """Extract file path from message."""
        # Look for paths in the format NTFS:\Path\To\File
        match = re.search(r'NTFS:\\(.+?)(?:$|,|\s)', message)
        if match:
            return match.group(1)

        # Look for "File reference" followed by a path
        match = re.search(r'File reference:.*?Parent file reference:.*?', message)
        if match:
            return match.group(0)

        return ""

    def _extract_url(self, message: str) -> str:
        """Extract URL from message."""
        # Look for URL pattern followed by title in parentheses
        match = re.search(r'(https?://[^\s()]+)\s*(\([^)]*\))?', message)
        if match:
            return match.group(1)
        return ""

    def _extract_visit_count(self, message: str) -> int:
        """Extract visit count from message."""
        match = re.search(r'Visit count:\s*(\d+)', message)
        if match:
            return int(match.group(1))
        return 0

    def _extract_visit_type(self, message: str) -> str:
        """Extract visit type from message."""
        match = re.search(r'Type:\s*\[([^\]]+)\]', message)
        if match:
            return match.group(1)
        return ""

    def analyze_url_patterns(self, urls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze URL patterns for credential-related activities.

        Args:
            urls: List of URL dictionaries

        Returns:
            Dictionary containing analysis results
        """
        login_patterns = re.compile(r'login|signin|sign-in|auth|account', re.IGNORECASE)
        banking_patterns = re.compile(r'bank|finance|account|transfer|payment', re.IGNORECASE)
        corporate_patterns = re.compile(r'corporate|admin|dashboard|portal', re.IGNORECASE)

        result = {
            'login_sites': [],
            'banking_sites': [],
            'corporate_sites': [],
            'high_frequency_sites': [],
            'typed_urls': [],
            'form_submission_urls': []
        }

        # Track domain frequencies
        domain_frequency = {}

        for url_data in urls:
            url = url_data.get('url', '')
            if not url:
                continue

            # Extract domain
            domain_match = re.search(r'https?://([^/]+)', url)
            if domain_match:
                domain = domain_match.group(1)
                domain_frequency[domain] = domain_frequency.get(domain, 0) + 1

            # Check for login-related URLs
            if login_patterns.search(url):
                result['login_sites'].append(url_data)

            # Check for banking-related URLs
            if banking_patterns.search(url):
                result['banking_sites'].append(url_data)

            # Check for corporate-related URLs
            if corporate_patterns.search(url):
                result['corporate_sites'].append(url_data)

            # Check for manually typed URLs
            visit_type = url_data.get('visit_type', '')
            if 'TYPED' in visit_type:
                result['typed_urls'].append(url_data)

            # Check for form submissions (may indicate credential entry)
            if 'FORM_SUBMIT' in visit_type:
                result['form_submission_urls'].append(url_data)

        # Identify high-frequency sites (top 10)
        sorted_domains = sorted(domain_frequency.items(), key=lambda x: x[1], reverse=True)
        for domain, count in sorted_domains[:10]:
            result['high_frequency_sites'].append({
                'domain': domain,
                'visit_count': count
            })

        return result

    def export_results(self, artifacts: Dict[str, List[Dict[str, Any]]], url_analysis: Dict[str, Any]) -> None:
        """
        Export analysis results to files.

        Args:
            artifacts: Dictionary of artifact data
            url_analysis: URL analysis results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save raw artifacts
        for artifact_type, data in artifacts.items():
            if data:
                with open(self.output_dir / f"{artifact_type}_{timestamp}.json", 'w') as f:
                    json.dump(data, f, indent=2)

                # Also save as CSV for easier viewing
                df = pd.DataFrame(data)
                df.to_csv(self.output_dir / f"{artifact_type}_{timestamp}.csv", index=False)

        # Save URL analysis
        with open(self.output_dir / f"url_analysis_{timestamp}.json", 'w') as f:
            json.dump(url_analysis, f, indent=2)

        # Create summary report
        self._generate_summary_report(artifacts, url_analysis, timestamp)

    def _generate_summary_report(self,
                               artifacts: Dict[str, List[Dict[str, Any]]],
                               url_analysis: Dict[str, Any],
                               timestamp: str) -> None:
        """Generate a summary report of findings."""
        with open(self.output_dir / f"credential_summary_{timestamp}.md", 'w') as f:
            f.write("# Browser Credential & Autofill Analysis Summary\n\n")
            f.write(f"Analysis performed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Summary statistics
            f.write("## Summary Statistics\n\n")
            f.write(f"- Login Data artifacts found: {len(artifacts['login_data'])}\n")
            f.write(f"- Autofill artifacts found: {len(artifacts['autofill'])}\n")
            f.write(f"- Browser extension artifacts found: {len(artifacts['extensions'])}\n")
            f.write(f"- Cookie artifacts found: {len(artifacts['cookies'])}\n")
            f.write(f"- URL visits analyzed: {len(artifacts['urls'])}\n\n")

            # Login sites
            f.write("## Login-Related Sites\n\n")
            if url_analysis['login_sites']:
                for i, site in enumerate(url_analysis['login_sites'][:20]):  # Limit to top 20
                    f.write(f"{i+1}. {site.get('url', 'Unknown URL')} (Visits: {site.get('visit_count', 0)})\n")
            else:
                f.write("No login-related sites identified.\n")
            f.write("\n")

            # Banking sites
            f.write("## Banking/Financial Sites\n\n")
            if url_analysis['banking_sites']:
                for i, site in enumerate(url_analysis['banking_sites'][:20]):  # Limit to top 20
                    f.write(f"{i+1}. {site.get('url', 'Unknown URL')} (Visits: {site.get('visit_count', 0)})\n")
            else:
                f.write("No banking-related sites identified.\n")
            f.write("\n")

            # High frequency sites
            f.write("## Most Frequently Visited Sites\n\n")
            if url_analysis['high_frequency_sites']:
                for i, site in enumerate(url_analysis['high_frequency_sites']):
                    f.write(f"{i+1}. {site.get('domain', 'Unknown domain')} (Visits: {site.get('visit_count', 0)})\n")
            else:
                f.write("No high-frequency sites identified.\n")
            f.write("\n")

            # Typed URLs (potential direct credential entry)
            f.write("## Manually Typed URLs\n\n")
            if url_analysis['typed_urls']:
                for i, site in enumerate(url_analysis['typed_urls'][:20]):  # Limit to top 20
                    f.write(f"{i+1}. {site.get('url', 'Unknown URL')}\n")
            else:
                f.write("No manually typed URLs identified.\n")
            f.write("\n")

            # Extensions (focus on LastPass)
            f.write("## Browser Extensions\n\n")
            lastpass_found = False
            for ext in artifacts['extensions']:
                if re.search(r'lastpass', str(ext), re.IGNORECASE):
                    lastpass_found = True
                    f.write(f"LastPass detected: {ext.get('path', 'Unknown path')}\n")
                    break

            if not lastpass_found:
                f.write("LastPass extension not definitively identified.\n")
            f.write("\n")

            # Recommendations
            f.write("## Analysis Recommendations\n\n")
            f.write("1. Examine Login Data SQLite databases for stored credentials\n")
            f.write("2. Analyze Autofill data for potentially exposed personal information\n")
            f.write("3. Review browser extension permissions, especially security extensions\n")
            f.write("4. Investigate high-frequency financial/corporate site visits\n")
            f.write("5. Check for evidence of credential exfiltration in form submission URLs\n")

    def run_analysis(self) -> None:
        """Run the complete credential analysis process."""
        logger.info("Starting credential analysis...")

        # Find all forensic CSV files
        csv_files, file_count = self.find_forensic_files()
        logger.info(f"Found {file_count} CSV files to process")

        # Scan for credential artifacts
        logger.info("Scanning for credential artifacts...")
        artifacts = self.scan_for_credential_artifacts(csv_files)

        # Analyze URL patterns
        logger.info("Analyzing URL patterns...")
        url_analysis = self.analyze_url_patterns(artifacts['urls'])

        # Export results
        logger.info("Exporting analysis results...")
        self.export_results(artifacts, url_analysis)

        logger.info("Credential analysis complete!")


def main():
    """Main function to run the credential analyzer."""
    import argparse

    parser = argparse.ArgumentParser(description='Analyze browser credential & autofill data')
    parser.add_argument('csv_dir', help='Directory containing CSV forensic data files')
    parser.add_argument('--output-dir', '-o', default='./credential_analysis',
                      help='Directory where analysis results will be saved')

    args = parser.parse_args()

    analyzer = CredentialAnalyzer(args.csv_dir, args.output_dir)
    analyzer.run_analysis()


if __name__ == '__main__':
    main()