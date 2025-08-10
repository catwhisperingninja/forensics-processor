#!/usr/bin/env python3
import os
import re
import pandas as pd
import argparse
from datetime import datetime
import glob
import urllib.parse


class GoogleDriveAnalyzer:
    """Analyzes browser history for Google Drive access and file details"""

    def __init__(self, data_dir, output_dir):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.drive_activities = []
        self.file_ids = {}  # Maps file IDs to details

    def _contains_google_drive_url(self, text):
        """Check if text contains a valid Google Drive URL"""
        if not isinstance(text, str):
            return False

        # First check for "Google Drive" text as a simple fallback
        if 'Google Drive' in text:
            return True

        # Extract URLs using regex
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)

        # Check each URL to see if it's a valid Google Drive URL
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname
                if hostname:
                    # Check if hostname is exactly drive.google.com or ends with .drive.google.com
                    if hostname == 'drive.google.com' or hostname.endswith('.drive.google.com'):
                        return True
            except Exception:
                # If URL parsing fails, skip this URL
                continue

        return False

    def find_csv_files(self):
        """Find all relevant CSV files in the data directory"""
        # Look for URL-based files first (they contain most browser activity)
        url_patterns = [
            os.path.join(self.data_dir, "urls_*.csv"),
            os.path.join(self.data_dir, "**", "urls_*.csv"),
            os.path.join(self.data_dir, "**", "imddbrowser*.csv"),
            os.path.join(self.data_dir, "imddbrowser*.csv"),
        ]

        csv_files = []
        for pattern in url_patterns:
            csv_files.extend(glob.glob(pattern, recursive=True))

        print(f"Found {len(csv_files)} CSV files to analyze")
        return csv_files

    def load_and_process_data(self):
        """Load data from CSV files and extract Google Drive information"""
        csv_files = self.find_csv_files()

        # Define patterns to match Google Drive URLs
        file_pattern = re.compile(r'https://drive\.google\.com/file/d/([^/]+)/view')
        folder_pattern = re.compile(r'https://drive\.google\.com/drive/u/\d+/folders/([^/\s\)]+)')
        # Updated title pattern to better extract filenames from Google Drive URLs
        title_pattern = re.compile(r'\(([^)]*?) - Google Drive\)')

        total_records = 0

        for csv_file in csv_files:
            try:
                print(f"Processing {csv_file}...")
                # Try to infer the format of the CSV file
                df = pd.read_csv(csv_file)

                # Look for expected columns in the CSV
                if 'url' in df.columns and 'timestamp' in df.columns:
                    # Process URL-specific CSV
                    for _, row in df.iterrows():
                        total_records += 1
                        self._process_drive_url(row['url'], row['timestamp'], file_pattern, folder_pattern, title_pattern)

                elif 'value' in df.columns and 'value' in df.columns:
                    # This is a message format CSV - process differently
                    for _, row in df.iterrows():
                        total_records += 1
                        if self._contains_google_drive_url(row['value']):
                            # This might contain drive info
                            self._process_drive_message(row['value'])

            except Exception as e:
                print(f"Error processing {csv_file}: {e}")

        print(f"Processed {total_records} total records")
        print(f"Extracted {len(self.file_ids)} unique Google Drive files/folders")

        # Post-process the data to improve folder/file names
        self._post_process_folder_names()

        return len(self.file_ids) > 0

    def _process_drive_url(self, url, timestamp, file_pattern, folder_pattern, title_pattern):
        """Process a single URL for Google Drive information"""
        if 'drive.google.com' not in str(url):
            return

        # Add to drive activities list
        activity_type = 'access'
        file_id = None
        file_name = None

        # Extract file ID and name if possible
        if 'file/d/' in str(url):
            # This is a file view
            file_match = file_pattern.search(str(url))
            if file_match:
                file_id = file_match.group(1)
                activity_type = 'file_view'

                # Try to extract file name from URL title if available
                title_match = title_pattern.search(str(url))
                if title_match:
                    file_name = title_match.group(1)

        elif 'folders/' in str(url):
            # This is a folder view
            folder_match = folder_pattern.search(str(url))
            if folder_match:
                file_id = folder_match.group(1)
                activity_type = 'folder_view'

                # Try to extract folder name
                title_match = title_pattern.search(str(url))
                if title_match:
                    file_name = title_match.group(1)

        # Add activity to list
        if file_id:
            activity = {
                'timestamp': timestamp,
                'url': url,
                'activity_type': activity_type,
                'file_id': file_id,
                'file_name': file_name or 'Unknown'
            }
            self.drive_activities.append(activity)

            # Store file ID and details
            if file_id not in self.file_ids:
                self.file_ids[file_id] = {
                    'file_id': file_id,
                    'file_name': file_name or 'Unknown',
                    'activity_type': activity_type,
                    'access_count': 1,
                    'first_access': timestamp,
                    'latest_access': timestamp
                }
            else:
                # Update existing file details
                self.file_ids[file_id]['access_count'] += 1

                # Update name if we got a better one
                if file_name and self.file_ids[file_id]['file_name'] == 'Unknown':
                    self.file_ids[file_id]['file_name'] = file_name

                # Update timestamps
                if timestamp < self.file_ids[file_id]['first_access']:
                    self.file_ids[file_id]['first_access'] = timestamp
                if timestamp > self.file_ids[file_id]['latest_access']:
                    self.file_ids[file_id]['latest_access'] = timestamp

    def _process_drive_message(self, message):
        """Process a message entry that might contain Google Drive information"""
        # Extract file ID and name from message
        file_id_match = re.search(r'drive\.google\.com/file/d/([^/\s\)]+)', message)
        if file_id_match:
            file_id = file_id_match.group(1)

            # Try to find a file name from Google Drive format
            file_name = 'Unknown'

            # Look for standard Google Drive format: (filename.ext - Google Drive)
            name_match = re.search(r'\(([^)]+) - Google Drive\)', message)
            if name_match:
                file_name = name_match.group(1)
            else:
                # Look for common file extensions
                name_match = re.search(r'([^\/\(\s]+\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt))', message, re.IGNORECASE)
                if name_match:
                    file_name = name_match.group(1)

            # Add to files dictionary
            if file_id not in self.file_ids:
                self.file_ids[file_id] = {
                    'file_id': file_id,
                    'file_name': file_name,
                    'activity_type': 'file_view',
                    'access_count': 1,
                    'first_access': 'unknown',
                    'latest_access': 'unknown'
                }
            elif self.file_ids[file_id]['file_name'] == 'Unknown' and file_name != 'Unknown':
                # Update with better filename if available
                self.file_ids[file_id]['file_name'] = file_name

    def _post_process_folder_names(self):
        """Post-process folder names to make report more readable"""
        # Based on our grep search, we found specific folder names to add
        folder_names = {
            'search_term_here': 'search_term_here',
        }

        # Known file names from grep search
        file_names = {
            'search_term_here': 'search_term_here.pdf',
        }

        # Update file/folder names
        for file_id, name in folder_names.items():
            if file_id in self.file_ids:
                self.file_ids[file_id]['file_name'] = name

        for file_id, name in file_names.items():
            if file_id in self.file_ids:
                self.file_ids[file_id]['file_name'] = name

        # Categorize files by type
        for file_id, details in self.file_ids.items():
            filename = details['file_name'].lower()

            # Add file type categorization
            if any(term in filename for term in ['tax', 'w2', '1098']):
                details['category'] = 'Tax Documents'
            elif any(term in filename for term in ['statement', 'ira', 'schwab', 'annual']):
                details['category'] = 'Financial Statements'
            elif any(term in filename for term in ['resume', 'cv']):
                details['category'] = 'Employment Documents'
            elif any(term in filename for term in ['paystub', 'pay stub']):
                details['category'] = 'Income Documents'
            elif any(term in filename for term in ['pip', 'accommodation', 'employer']):
                details['category'] = 'HR Documents'
            elif any(term in filename for term in ['marriage', 'divorce', 'certificate']):
                details['category'] = 'Legal Documents'
            else:
                details['category'] = 'Other Documents'

    def generate_reports(self):
        """Generate markdown and CSV reports for Google Drive activity"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Convert file dictionary to DataFrame for reporting
        files_df = pd.DataFrame(list(self.file_ids.values()))

        # Save complete CSV data
        csv_path = os.path.join(self.output_dir, f"drive_files_{timestamp}.csv")
        files_df.to_csv(csv_path, index=False)
        print(f"Saved Google Drive files data to {csv_path}")

        # Save activities CSV if available
        if self.drive_activities:
            activities_df = pd.DataFrame(self.drive_activities)
            activities_path = os.path.join(self.output_dir, f"drive_activities_{timestamp}.csv")
            activities_df.to_csv(activities_path, index=False)
            print(f"Saved Google Drive activities data to {activities_path}")

        # Generate markdown report
        report_path = os.path.join(self.output_dir, f"drive_summary_{timestamp}.md")
        with open(report_path, 'w') as f:
            f.write("# Google Drive Activity Analysis\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            # Overall statistics
            f.write("## Overall Statistics\n\n")
            f.write(f"- Total Unique Google Drive Files/Folders: {len(self.file_ids)}\n")
            if self.drive_activities:
                f.write(f"- Total Google Drive Activities: {len(self.drive_activities)}\n")
            f.write("\n")

            # Files by category (if categorized)
            if 'category' in files_df.columns:
                f.write("## Files by Category\n\n")
                categories = files_df['category'].value_counts().to_dict()
                for category, count in categories.items():
                    f.write(f"- {category}: {count}\n")
                f.write("\n")

                # List files by category
                for category in sorted(files_df['category'].unique()):
                    f.write(f"### {category}\n\n")
                    category_files = files_df[files_df['category'] == category].sort_values('access_count', ascending=False)

                    for _, row in category_files.iterrows():
                        f.write(f"- **{row['file_name']}** (ID: {row['file_id']})\n")
                        f.write(f"  - Access Count: {row['access_count']}\n")
                        f.write(f"  - Activity Type: {row['activity_type']}\n")
                        if 'first_access' in row and row['first_access'] != 'unknown':
                            f.write(f"  - First Access: {row['first_access']}\n")
                        if 'latest_access' in row and row['latest_access'] != 'unknown':
                            f.write(f"  - Latest Access: {row['latest_access']}\n")
                        f.write("\n")
            else:
                # Most accessed files
                f.write("## Most Accessed Files/Folders\n\n")
                if not files_df.empty:
                    # Sort by access count if available
                    if 'access_count' in files_df.columns:
                        top_files = files_df.sort_values('access_count', ascending=False).head(10)
                        for _, row in top_files.iterrows():
                            f.write(f"- **{row['file_name']}** (ID: {row['file_id']})\n")
                            f.write(f"  - Access Count: {row['access_count']}\n")
                            f.write(f"  - Activity Type: {row['activity_type']}\n")
                            if 'first_access' in row and row['first_access'] != 'unknown':
                                f.write(f"  - First Access: {row['first_access']}\n")
                            if 'latest_access' in row and row['latest_access'] != 'unknown':
                                f.write(f"  - Latest Access: {row['latest_access']}\n")
                            f.write("\n")
                    else:
                        # Just list all files
                        for _, row in files_df.iterrows():
                            f.write(f"- **{row['file_name']}** (ID: {row['file_id']})\n")
                            f.write("\n")
                else:
                    f.write("*No Google Drive files detected*\n\n")

            # Folder analysis if available
            folder_data = files_df[files_df['activity_type'] == 'folder_view'] if not files_df.empty else pd.DataFrame()
            if not folder_data.empty:
                f.write("## Google Drive Folders\n\n")
                for _, row in folder_data.iterrows():
                    f.write(f"- **{row['file_name']}** (ID: {row['file_id']})\n")
                    if 'access_count' in row:
                        f.write(f"  - Access Count: {row['access_count']}\n")
                    if 'first_access' in row and row['first_access'] != 'unknown':
                        f.write(f"  - First Access: {row['first_access']}\n")
                    if 'latest_access' in row and row['latest_access'] != 'unknown':
                        f.write(f"  - Latest Access: {row['latest_access']}\n")
                    f.write("\n")

            # Timeline section if we have timestamp data
            if self.drive_activities:
                f.write("## Google Drive Activity Timeline\n\n")
                # Sort activities by timestamp
                activities_df = pd.DataFrame(self.drive_activities)
                activities_df = activities_df.sort_values('timestamp')

                # Limit the timeline to the most recent 50 activities to avoid overwhelming output
                recent_activities = activities_df.tail(50)
                for _, row in recent_activities.iterrows():
                    f.write(f"- {row['timestamp']}: {row['activity_type']} - **{row['file_name']}**\n")

                if len(activities_df) > 50:
                    f.write(f"\n*Note: Timeline limited to 50 most recent activities out of {len(activities_df)} total.*\n")

                f.write("\n")

        print(f"Generated Google Drive summary report at {report_path}")
        return report_path


def main():
    parser = argparse.ArgumentParser(description='Analyze browser history for Google Drive activity')
    parser.add_argument('--data-dir', required=True, help='Directory containing CSV data files')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run analyzer
    analyzer = GoogleDriveAnalyzer(args.data_dir, args.output_dir)
    if analyzer.load_and_process_data():
        analyzer.generate_reports()
        print("Analysis complete!")
    else:
        print("No Google Drive activity found in the provided data.")


if __name__ == "__main__":
    main()