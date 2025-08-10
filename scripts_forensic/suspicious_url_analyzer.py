#!/usr/bin/env python3
import os
import re
import json
import pandas as pd
from datetime import datetime
import argparse


class SuspiciousURLAnalyzer:
    """Analyzes browser history for suspicious URLs and generates reports"""

    def __init__(self, url_csv_path, output_dir):
        self.url_csv_path = url_csv_path
        self.output_dir = output_dir
        self.urls_df = None
        self.unique_urls = None
        self.flagged_urls = None

        # Initialize suspicious URL patterns
        self.suspicious_patterns = {
            'porn': [
                r'(?i)porn', r'(?i)xxx', r'(?i)adult', r'(?i)sex',
                r'(?i)redtube', r'(?i)xvideos', r'(?i)pornhub'
            ],
            'tor': [
                r'\.onion$', r'(?i)tor(project|browser)\.org',
                r'(?i)hidden\s*service', r'(?i)(dark|deep)\s*web',
                r'(?i)darknet', r'(?i)anonymity\s*network'
            ],
            'blockchain': [
                r'(?i)blockchain', r'(?i)bitcoin', r'(?i)ethereum',
                r'(?i)crypto', r'(?i)wallet', r'(?i)coinbase',
                r'(?i)binance', r'(?i)etherscan', r'(?i)explorer'
            ],
            'data_exfil': [
                r'(?i)pastebin', r'(?i)wetransfer', r'(?i)megaupload',
                r'(?i)dropbox', r'(?i)box.com', r'(?i)temp-mail',
                r'(?i)tempmail', r'(?i)anonymous'
            ],
            'suspicious_files': [
                r'\.exe$', r'\.zip$', r'\.rar$', r'\.7z$',
                r'\.tar\.gz$', r'\.sh$', r'\.bat$', r'\.ps1$'
            ],
            'cloud_storage': [
                r'drive\.google\.com', r'docs\.google\.com',
                r'onedrive\.live\.com', r'sharepoint\.com',
                r'icloud\.com', r'box\.com', r'dropbox\.com'
            ]
        }

        # Domains to explicitly exclude from tor category
        self.exclude_domains = [
            'google.com', 'googleapis.com', 'microsoft.com',
            'office.com', 'github.com', 'apple.com'
        ]

    def load_data(self):
        """Load URL data from CSV file"""
        print(f"Loading data from {self.url_csv_path}")
        try:
            # CSV has the columns: timestamp,message,source,url,visit_count,visit_type
            self.urls_df = pd.read_csv(self.url_csv_path)
            print(f"Loaded {len(self.urls_df)} URL records")
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False

    def process_urls(self):
        """Process URLs to extract unique entries and count visits"""
        # Our CSV has actual URL in the 'url' column (column index 3)
        # and timestamp in the first column

        # Create a DataFrame with clean data
        url_data = pd.DataFrame({
            'timestamp': self.urls_df['timestamp'],
            'url': self.urls_df['url'],
            'visit_count': self.urls_df['visit_count'],
            'visit_type': self.urls_df['visit_type']
        })

        # Get unique URLs with counts
        # Group by URL and aggregate
        url_counts = url_data.groupby('url').agg({
            'visit_count': 'sum',  # Sum all visit counts for the same URL
            'timestamp': lambda x: list(x)  # Collect all timestamps for the URL
        }).reset_index()

        # Convert timestamp lists to JSON strings for storage
        url_counts['timestamps'] = url_counts['timestamp'].apply(json.dumps)
        url_counts.drop('timestamp', axis=1, inplace=True)

        self.unique_urls = url_counts
        print(f"Processed {len(self.unique_urls)} unique URLs")
        return self.unique_urls

    def detect_suspicious_urls(self):
        """Flag suspicious URLs based on patterns"""
        if self.unique_urls is None:
            print("No URLs to analyze")
            return None

        # Add columns for each suspicious category
        for category, patterns in self.suspicious_patterns.items():
            self.unique_urls[category] = self.unique_urls['url'].apply(
                lambda url: any(re.search(pattern, url) for pattern in patterns)
            )

        # Fix Tor misidentification by excluding major domains
        # This prevents Google OAuth URLs from being flagged as Tor
        self.unique_urls['tor'] = self.unique_urls.apply(
            lambda row: row['tor'] and not any(domain in row['url'] for domain in self.exclude_domains),
            axis=1
        )

        # Create a 'flagged' column if any suspicious pattern matches
        self.unique_urls['flagged'] = self.unique_urls[[
            'porn', 'tor', 'blockchain', 'data_exfil', 'suspicious_files'
        ]].any(axis=1)

        # Extract flagged URLs
        self.flagged_urls = self.unique_urls[self.unique_urls['flagged']]
        print(f"Detected {len(self.flagged_urls)} suspicious URLs")
        return self.flagged_urls

    def generate_reports(self):
        """Generate markdown and CSV reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save detailed URLs CSV
        detailed_path = os.path.join(self.output_dir, f"detailed_urls_{timestamp}.csv")
        self.unique_urls.to_csv(detailed_path, index=False)
        print(f"Saved detailed URL data to {detailed_path}")

        # Save flagged URLs CSV
        if self.flagged_urls is not None and not self.flagged_urls.empty:
            flagged_path = os.path.join(self.output_dir, f"flagged_urls_{timestamp}.csv")
            self.flagged_urls.to_csv(flagged_path, index=False)
            print(f"Saved flagged URLs to {flagged_path}")

        # Generate markdown report
        report_path = os.path.join(self.output_dir, f"summary_report_{timestamp}.md")
        with open(report_path, 'w') as f:
            f.write("# Browser History Suspicious Behavior Report\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            # Overall statistics
            f.write("## Overall Statistics\n\n")
            f.write(f"- Total Unique URLs: {len(self.unique_urls)}\n")
            f.write(f"- Flagged Suspicious URLs: {len(self.flagged_urls) if self.flagged_urls is not None else 0}\n\n")

            # Suspicious categories breakdown
            f.write("## Suspicious Categories Breakdown\n\n")
            for category in self.suspicious_patterns:
                count = self.unique_urls[category].sum()
                f.write(f"- {category.replace('_', ' ').title()}: {count}\n")
            f.write("\n")

            # Top visited URLs
            f.write("## Top 10 Most Visited URLs\n\n")
            top_urls = self.unique_urls.sort_values('visit_count', ascending=False).head(10)
            for _, row in top_urls.iterrows():
                f.write(f"- {row['url']} (Visits: {row['visit_count']})\n")
            f.write("\n")

            # Cloud storage URLs
            f.write("## Cloud Storage URLs\n\n")
            cloud_urls = self.unique_urls[self.unique_urls['cloud_storage']].sort_values('visit_count', ascending=False)
            if not cloud_urls.empty:
                for _, row in cloud_urls.iterrows():
                    f.write(f"- {row['url']} (Visits: {row['visit_count']})\n")

                    # Add timestamps for this URL
                    timestamps = json.loads(row['timestamps'])
                    if timestamps:
                        f.write("  - Visit timestamps:\n")
                        for ts in timestamps[:5]:  # Limit to 5 timestamps to avoid overwhelming output
                            f.write(f"    - {ts}\n")
                        if len(timestamps) > 5:
                            f.write(f"    - ... and {len(timestamps) - 5} more visits\n")
            else:
                f.write("*No cloud storage URLs detected*\n")
            f.write("\n")

            # Suspicious URLs section
            f.write("## Flagged Suspicious URLs\n\n")
            if self.flagged_urls is not None and not self.flagged_urls.empty:
                for _, row in self.flagged_urls.iterrows():
                    categories = []
                    for category in self.suspicious_patterns:
                        if row[category] and category != 'cloud_storage':  # Don't include cloud_storage in flagged categories
                            categories.append(category.replace('_', ' ').title())

                    category_str = ", ".join(categories)
                    f.write(f"- {row['url']} (Visits: {row['visit_count']}, Categories: {category_str})\n")

                    # Add timestamps for this URL
                    timestamps = json.loads(row['timestamps'])
                    if timestamps:
                        f.write("  - Visit timestamps:\n")
                        for ts in timestamps[:5]:  # Limit to 5 timestamps to avoid overwhelming output
                            f.write(f"    - {ts}\n")
                        if len(timestamps) > 5:
                            f.write(f"    - ... and {len(timestamps) - 5} more visits\n")
            else:
                f.write("*No suspicious URLs detected*\n")

        print(f"Generated summary report at {report_path}")
        return report_path


def main():
    parser = argparse.ArgumentParser(description='Analyze browser history for suspicious URLs')
    parser.add_argument('--url-csv', required=True, help='Path to the URL CSV file')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run analyzer
    analyzer = SuspiciousURLAnalyzer(args.url_csv, args.output_dir)
    if analyzer.load_data():
        analyzer.process_urls()
        analyzer.detect_suspicious_urls()
        analyzer.generate_reports()
        print("Analysis complete!")
    else:
        print("Failed to load data. Aborting analysis.")


if __name__ == "__main__":
    main()