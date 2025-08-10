#!/usr/bin/env python3
"""
De-anonymization script for credential analysis data.
Replaces sensitive strings with "REDACTED" while preserving original files.
"""

import json
import shutil
import os
from datetime import datetime
import re
import sys

# Sensitive strings to replace
USERNAME = "search_term_here"
FULL_NAME = "search_term_here"
LOCATION_FULL = "search_term_here"
LOCATION_ALT = "search_term_here"
LOCATION_ABBREV = "search_term_here"
INITIALS = "search_term_here"

# Replacement value
REPLACEMENT_TEXT = "REDACTED"

# Build replacements dictionary from variables
REPLACEMENTS = {
    USERNAME: REPLACEMENT_TEXT,
    FULL_NAME: REPLACEMENT_TEXT,
    LOCATION_FULL: REPLACEMENT_TEXT,
    LOCATION_ALT: REPLACEMENT_TEXT,
    LOCATION_ABBREV: REPLACEMENT_TEXT,
    INITIALS: REPLACEMENT_TEXT
}

def create_backup(filepath):
    """Create a backup of the original file with .original extension"""
    backup_path = filepath + ".original"
    shutil.copy2(filepath, backup_path)
    print(f"Created backup: {backup_path}")
    return backup_path

def replace_in_string(text):
    """Replace all occurrences of sensitive strings (case-insensitive)"""
    if not isinstance(text, str):
        return text

    # Sort by length (descending) to replace longer strings first
    sorted_replacements = sorted(REPLACEMENTS.items(), key=lambda x: len(x[0]), reverse=True)

    for original, replacement in sorted_replacements:
        # Use word boundaries for short strings like initials and acronyms
        if len(original) <= 3:
            pattern = r'\b' + re.escape(original) + r'\b'
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        else:
            # For longer strings, do case-insensitive replacement
            text = re.sub(re.escape(original), replacement, text, flags=re.IGNORECASE)

    return text

def process_json_value(value):
    """Recursively process JSON values"""
    if isinstance(value, str):
        return replace_in_string(value)
    elif isinstance(value, list):
        return [process_json_value(item) for item in value]
    elif isinstance(value, dict):
        return {k: process_json_value(v) for k, v in value.items()}
    else:
        return value

def process_json_file(filepath):
    """Process a JSON file and replace sensitive strings"""
    print(f"\nProcessing: {filepath}")

    # Create backup first
    create_backup(filepath)

    # Read the JSON file
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Process the data
    processed_data = process_json_value(data)

    # Write the de-anonymized data
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(processed_data, f, indent=2, ensure_ascii=False)

    print(f"De-anonymized: {filepath}")

def main():
    """Main function to process all files"""

    # Check if file path is provided as argument
    if len(sys.argv) < 2:
        print("Usage: python anonymize.py <json_file_path>")
        print("Example: python anonymize.py autofill_20250330_113528.json")
        sys.exit(1)

    filepath = sys.argv[1]

    # Check if file exists
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    # Check if it's a JSON file
    if not filepath.endswith('.json'):
        print(f"Error: File must be a JSON file: {filepath}")
        sys.exit(1)

    print("Starting de-anonymization process...")
    print(f"File: {filepath}")
    print(f"\nStrings to replace with '{REPLACEMENT_TEXT}':")
    print(f"  - Username: {USERNAME}")
    print(f"  - Full name: {FULL_NAME}")
    print(f"  - Location: {LOCATION_FULL}")
    print(f"  - Location alt: {LOCATION_ALT}")
    print(f"  - Location abbrev: {LOCATION_ABBREV}")
    print(f"  - Initials: {INITIALS}")

    # Process the file
    process_json_file(filepath)

    print("\n✓ De-anonymization complete!")
    print("Original file has been backed up with .original extension")

if __name__ == "__main__":
    main()