#!/usr/bin/env python3
"""
Anonymization script for markdown files.
Replaces sensitive strings with "REDACTED" while preserving original files.

Usage:
    python anonymize_md.py

Note: Currently targets a hardcoded file (TARGET_FILE variable).
To modify for command-line usage, update the script to accept sys.argv[1] as the target file.
"""

import shutil
import os
from datetime import datetime
import re

# Sensitive strings to replace
USERNAME = "search_term_here"
FULL_NAME = "search_term_here"
LOCATION_FULL = "search_term_here"
LOCATION_ALT = "search_term_here"
LOCATION_ABBREV = "search_term_here"
INITIALS = "search_term_here"

# Replacement value
REPLACEMENT_TEXT = "REDACTED"

# Target file to anonymize
TARGET_FILE = "filename.md"

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
        # Use word boundaries for short strings initials and acronyms
        if len(original) <= 3:
            pattern = r'\b' + re.escape(original) + r'\b'
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        else:
            # For longer strings, do case-insensitive replacement
            text = re.sub(re.escape(original), replacement, text, flags=re.IGNORECASE)

    return text

def process_markdown_file(filepath):
    """Process a markdown file and replace sensitive strings"""
    print(f"\nProcessing: {filepath}")

    # Create backup first
    create_backup(filepath)

    # Read the markdown file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Process the content
    processed_content = replace_in_string(content)

    # Write the anonymized data
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(processed_content)

    print(f"Anonymized: {filepath}")

def main():
    """Main function to process the credential summary markdown file"""
    print("Starting anonymization process for markdown file...")
    print(f"Target file: {TARGET_FILE}")
    print(f"\nStrings to replace with '{REPLACEMENT_TEXT}':")
    print(f"  - Username: {USERNAME}")
    print(f"  - Full name: {FULL_NAME}")
    print(f"  - Location: {LOCATION_FULL}")
    print(f"  - Location alt: {LOCATION_ALT}")
    print(f"  - Location abbrev: {LOCATION_ABBREV}")
    print(f"  - Initials: {INITIALS}")

    # Process the file
    if os.path.exists(TARGET_FILE):
        process_markdown_file(TARGET_FILE)
    else:
        print(f"\nError: File not found: {TARGET_FILE}")
        return

    print("\n✓ Anonymization complete!")
    print("Original file has been backed up with .original extension")

if __name__ == "__main__":
    main()