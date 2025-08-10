#!/usr/bin/env python3
"""
Sanitize OAuth tokens and credentials in JSON files to bypass GitHub secret scanning
while maintaining the forensic analysis value.
"""

import json
import re
import sys
from pathlib import Path

def sanitize_token(token):
    """
    Sanitize a token by replacing middle characters with XXX
    while keeping first and last few characters for identification
    """
    if len(token) > 20:
        # Keep first 6 and last 6 characters
        return token[:6] + "XXX" + token[-6:]
    elif len(token) > 10:
        # Keep first 3 and last 3 characters
        return token[:3] + "XXX" + token[-3:]
    else:
        # Short tokens - just replace middle
        return token[:2] + "X" + token[-2:] if len(token) > 4 else token

def sanitize_json_content(content):
    """
    Find and sanitize various token patterns in JSON content
    """
    # Patterns for different token types
    patterns = [
        # AWS Secret Keys (40 chars starting with specific patterns)
        (r'([A-Za-z0-9+/]{40})', lambda m: sanitize_token(m.group(1)) if len(m.group(1)) == 40 else m.group(1)),
        # JWT tokens (eyJ...)
        (r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', lambda m: sanitize_token(m.group(1))),
        # OAuth tokens in various formats
        (r'(token=)([A-Za-z0-9_-]{20,})', lambda m: m.group(1) + sanitize_token(m.group(2))),
        (r'(access_token["\s]*[:=]\s*["\s]*)([A-Za-z0-9_-]{20,})', lambda m: m.group(1) + sanitize_token(m.group(2))),
        # General long alphanumeric strings that might be tokens
        (r'([A-Za-z0-9]{32,})', lambda m: sanitize_token(m.group(1)) if len(m.group(1)) > 32 else m.group(1)),
    ]
    
    result = content
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)
    
    return result

def process_json_file(file_path):
    """Process a single JSON file"""
    print(f"Processing: {file_path}")
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Sanitize the content
        sanitized = sanitize_json_content(content)
        
        # Write back if changed
        if content != sanitized:
            with open(file_path, 'w') as f:
                f.write(sanitized)
            print(f"  ✓ Sanitized tokens in {file_path}")
        else:
            print(f"  - No tokens found to sanitize")
            
    except Exception as e:
        print(f"  ✗ Error processing {file_path}: {e}")

def main():
    # Find all JSON files in the credential analysis directories
    base_path = Path("500k-csv-splits/batch_analysis/credential_analysis_full")
    json_files = list(base_path.glob("**/*.json"))
    
    print(f"Found {len(json_files)} JSON files to process")
    
    for json_file in json_files:
        process_json_file(json_file)
    
    print("\nDone! Tokens have been sanitized while preserving forensic value.")
    print("You should now be able to push to GitHub without triggering secret scanning.")

if __name__ == "__main__":
    main()