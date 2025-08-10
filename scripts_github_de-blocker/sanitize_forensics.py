#!/usr/bin/env python3
"""
Sanitize forensics files to remove patterns that GitHub detects as secrets
while preserving the forensic analysis value of the data.
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# AWS Secret Key pattern: 40 character base64 string
AWS_SECRET_PATTERN = re.compile(r'[A-Za-z0-9/+=]{40}')

# AWS Access Key ID pattern: starts with AKIA, ABIA, ACCA, or ASIA followed by 16 alphanumeric
AWS_ACCESS_KEY_PATTERN = re.compile(r'A[BCIS][KI]A[A-Z0-9]{16}')

# Generic API key patterns that might trigger false positives
GENERIC_API_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{20,})', re.IGNORECASE),
    re.compile(r'(?i)(secret[_-]?key|secret[_-]?token|private[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{20,})', re.IGNORECASE),
    re.compile(r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=!@#$%^&*()]{8,})', re.IGNORECASE),
    re.compile(r'(?i)(token|auth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=_-]{20,})', re.IGNORECASE),
    re.compile(r'(?i)(client[_-]?secret|app[_-]?secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{20,})', re.IGNORECASE),
    # GitHub token pattern
    re.compile(r'ghp_[A-Za-z0-9]{36}'),
    re.compile(r'gho_[A-Za-z0-9]{36}'),
    re.compile(r'ghs_[A-Za-z0-9]{36}'),
    re.compile(r'ghr_[A-Za-z0-9]{36}'),
    # Generic base64 patterns that might be secrets
    re.compile(r'[A-Za-z0-9+/]{32,}={0,2}'),
]

def sanitize_aws_patterns(text: str) -> Tuple[str, int]:
    """Replace AWS-like patterns with sanitized versions."""
    count = 0

    # Replace AWS secret keys (40 char base64)
    def replace_secret(match):
        nonlocal count
        count += 1
        secret = match.group(0)
        # Don't include any part of the actual secret
        return f"[AWS_SECRET_REDACTED_{count}]"

    text = AWS_SECRET_PATTERN.sub(replace_secret, text)

    # Replace AWS access keys
    def replace_access(match):
        nonlocal count
        count += 1
        return f"[AWS_ACCESS_KEY_REDACTED_{count}]"

    text = AWS_ACCESS_KEY_PATTERN.sub(replace_access, text)

    return text, count

def sanitize_generic_patterns(text: str) -> Tuple[str, int]:
    """Replace generic API key patterns."""
    count = 0

    for pattern in GENERIC_API_PATTERNS:
        def replace_pattern(match):
            nonlocal count
            count += 1

            # For patterns with groups (key=value patterns)
            if match.lastindex and match.lastindex >= 1:
                key_name = match.group(1)
                return f"{key_name}=[REDACTED_{count}]"
            else:
                # For standalone patterns like GitHub tokens
                return f"[REDACTED_{count}]"

        text = pattern.sub(replace_pattern, text)

    return text, count

def sanitize_file(file_path: Path, output_path: Optional[Path] = None, verbose: bool = False) -> Dict[str, int]:
    """Sanitize a single file."""
    if output_path is None:
        output_path = file_path.with_suffix(file_path.suffix + '.sanitized')

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return {"error": 1}

    original_length = len(content)

    # Apply sanitization
    sanitized_content = content
    aws_count = 0
    generic_count = 0

    sanitized_content, aws_count = sanitize_aws_patterns(sanitized_content)
    sanitized_content, generic_count = sanitize_generic_patterns(sanitized_content)

    if verbose and (aws_count > 0 or generic_count > 0):
        print(f"  Original size: {original_length}, Sanitized size: {len(sanitized_content)}")

    # Write sanitized content
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sanitized_content)
    except Exception as e:
        print(f"Error writing {output_path}: {e}")
        return {"error": 1}

    return {
        "aws_patterns": aws_count,
        "generic_patterns": generic_count,
        "total": aws_count + generic_count
    }

def should_skip_path(path: Path, skip_hidden: bool, skip_all_dots: bool) -> bool:
    """Check if a path should be skipped based on dot directory rules."""
    parts = path.parts

    if skip_all_dots:
        # Skip if any directory in the path starts with a dot
        return any(part.startswith('.') for part in parts)
    elif skip_hidden:
        # Skip only if the immediate parent or file starts with a dot (not ./)
        return any(part.startswith('.') and part != '.' for part in parts)

    return False

def sanitize_directory(
    input_dir: Path,
    output_dir: Path,
    extensions: Optional[List[str]] = None,
    skip_hidden: bool = True,
    skip_all_dots: bool = False,
    verbose: bool = False
) -> Dict[str, int]:
    """Sanitize all files in a directory recursively."""
    if extensions is None:
        extensions = ['.json', '.txt', '.log', '.csv', '.xml', '.yml', '.yaml', '.conf', '.config', '.ini']

    total_stats = {"files": 0, "patterns": 0, "skipped": 0}

    # Convert to lowercase for comparison
    extensions_lower = [ext.lower() for ext in extensions]

    print(f"Scanning directory: {input_dir}")
    print(f"Looking for extensions: {extensions}")
    print(f"Skip hidden dirs: {skip_hidden}, Skip all dot dirs: {skip_all_dots}\n")

    # Use rglob to recursively find all files
    all_files = list(input_dir.rglob('*'))
    print(f"Found {len(all_files)} total items in directory tree")

    for file_path in all_files:
        if file_path.is_file():
            # Check if we should skip this file
            if should_skip_path(file_path, skip_hidden, skip_all_dots):
                total_stats["skipped"] += 1
                if verbose:
                    print(f"Skipping (dot directory): {file_path.relative_to(input_dir)}")
                continue

            # Check extension
            if extensions and file_path.suffix.lower() not in extensions_lower:
                if verbose:
                    print(f"Skipping (extension): {file_path.relative_to(input_dir)}")
                continue

            relative_path = file_path.relative_to(input_dir)
            output_path = output_dir / relative_path

            print(f"Sanitizing: {relative_path}")
            stats = sanitize_file(file_path, output_path, verbose)

            if "error" not in stats:
                total_stats["files"] += 1
                total_stats["patterns"] += stats["total"]
                if stats["total"] > 0:
                    print(f"  Found and sanitized {stats['total']} patterns")

    return total_stats

def main():
    parser = argparse.ArgumentParser(description="Sanitize forensics files to remove secret-like patterns")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("-o", "--output", help="Output file or directory (default: adds .sanitized suffix)")
    parser.add_argument("-e", "--extensions", nargs="+", help="File extensions to process (for directories)")
    parser.add_argument("--skip-hidden", action="store_true", default=True,
                        help="Skip hidden directories (starting with .) - default: True")
    parser.add_argument("--include-hidden", action="store_true",
                        help="Include hidden directories")
    parser.add_argument("--skip-all-dots", action="store_true",
                        help="Skip ALL directories with dots anywhere in path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--test", action="store_true", help="Test mode - show what would be sanitized")

    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        print(f"Error: {input_path} does not exist")
        sys.exit(1)

    if input_path.is_file():
        output_path = Path(args.output) if args.output else None
        stats = sanitize_file(input_path, output_path, args.verbose)
        print(f"\nSanitization complete: {stats}")
    else:
        output_path = Path(args.output) if args.output else input_path.parent / f"{input_path.name}_sanitized"
        skip_hidden = not args.include_hidden
        stats = sanitize_directory(
            input_path,
            output_path,
            args.extensions,
            skip_hidden=skip_hidden,
            skip_all_dots=args.skip_all_dots,
            verbose=args.verbose
        )
        print(f"\nSanitization complete:")
        print(f"  Files processed: {stats['files']}")
        print(f"  Patterns sanitized: {stats['patterns']}")
        print(f"  Files skipped: {stats['skipped']}")

if __name__ == "__main__":
    main()