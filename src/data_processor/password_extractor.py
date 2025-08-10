#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Password Extractor for Browser Forensics Data
This module focuses on extracting potential plaintext passwords and credentials from browser forensic data.
"""

import os
import re
import csv
import json
import logging
import pandas as pd
import base64
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set, Optional, Union
from datetime import datetime
import urllib.parse
import glob
import argparse
import binascii

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PasswordExtractor:
    """Extract potential plaintext passwords and credentials from browser forensics data."""

    def __init__(self, input_dir: str, output_dir: str, ctf_focus: bool = False):
        """
        Initialize the password extractor.

        Args:
            input_dir: Directory containing the browser forensic CSV files or processed data
            output_dir: Directory where extraction results will be saved
            ctf_focus: Whether to focus on CTF flag patterns
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ctf_focus = ctf_focus

        # Common password-related patterns - REFINED to exclude tokens
        self.password_field_patterns = [
            re.compile(r'type=["\']password["\']', re.IGNORECASE),
            re.compile(r'input[^>]*?type=["\']password["\']', re.IGNORECASE),
            re.compile(r'name=["\']password["\']', re.IGNORECASE),
            re.compile(r'name=["\']passwd["\']', re.IGNORECASE),
            re.compile(r'name=["\']pass["\']', re.IGNORECASE),
            re.compile(r'name=["\']pwd["\']', re.IGNORECASE),
            re.compile(r'id=["\']password["\']', re.IGNORECASE),
            re.compile(r'id=["\']passwd["\']', re.IGNORECASE),
            re.compile(r'id=["\']pass["\']', re.IGNORECASE),
            re.compile(r'id=["\']pwd["\']', re.IGNORECASE),
            # The key pattern: matching password parameters in POST data
            re.compile(r'[?&]password=([^&]+)', re.IGNORECASE),
            re.compile(r'[?&]passwd=([^&]+)', re.IGNORECASE),
            re.compile(r'[?&]pass=([^&]+)', re.IGNORECASE),
            re.compile(r'[?&]pwd=([^&]+)', re.IGNORECASE),
        ]

        # Exclude patterns - tokens that are NOT passwords
        self.token_exclusion_patterns = [
            re.compile(r'token=', re.IGNORECASE),
            re.compile(r'bearer\s+', re.IGNORECASE),
            re.compile(r'access_token=', re.IGNORECASE),
            re.compile(r'refresh_token=', re.IGNORECASE),
            re.compile(r'id_token=', re.IGNORECASE),
            re.compile(r'session_token=', re.IGNORECASE),
            re.compile(r'sessiontoken=', re.IGNORECASE),
            re.compile(r'csrf_token=', re.IGNORECASE),
            re.compile(r'csrftoken=', re.IGNORECASE),
            re.compile(r'auth_token=', re.IGNORECASE),
            re.compile(r'authtoken=', re.IGNORECASE),
            re.compile(r'oauth_token=', re.IGNORECASE),
            re.compile(r'oauthtoken=', re.IGNORECASE),
            re.compile(r'api_key=', re.IGNORECASE),
            re.compile(r'apikey=', re.IGNORECASE),
            re.compile(r'jwtoken=', re.IGNORECASE),
            re.compile(r'jwt=', re.IGNORECASE),
            re.compile(r'membertoken=', re.IGNORECASE),
            re.compile(r'midtoken=', re.IGNORECASE),
            re.compile(r'otptoken=', re.IGNORECASE),
            re.compile(r'eyJ', re.IGNORECASE),  # JWT token pattern
        ]

        # CTF flag patterns
        self.ctf_flag_patterns = [
            re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
            re.compile(r'key\{[^}]+\}', re.IGNORECASE),
            re.compile(r'CTF\{[^}]+\}', re.IGNORECASE),
            re.compile(r'KEY_[A-Z_]+', re.IGNORECASE),
            re.compile(r'PASSWORD\{[^}]+\}', re.IGNORECASE)
        ]

        # HTTP request patterns with potential credentials
        self.http_request_patterns = [
            re.compile(r'POST.*login', re.IGNORECASE),
            re.compile(r'POST.*signin', re.IGNORECASE),
            re.compile(r'POST.*auth', re.IGNORECASE),
            re.compile(r'GET.*token=([^&]+)', re.IGNORECASE),
            re.compile(r'Basic\s+([a-zA-Z0-9+/=]+)', re.IGNORECASE),  # Basic auth
            re.compile(r'Bearer\s+([a-zA-Z0-9._-]+)', re.IGNORECASE)  # Bearer token
        ]

        # Common encoded credential patterns
        self.encoded_patterns = [
            re.compile(r'[a-zA-Z0-9+/]{20,}={0,2}')  # Potential base64
        ]

        # Form field patterns targeting password fields
        self.form_field_patterns = [
            re.compile(r'<input[^>]*?type=["\']password["\'][^>]*?>', re.IGNORECASE),
            re.compile(r'name=["\']password["\']', re.IGNORECASE),
            re.compile(r'name=["\']passwd["\']', re.IGNORECASE),
            re.compile(r'name=["\']pass["\']', re.IGNORECASE),
            re.compile(r'name=["\']pwd["\']', re.IGNORECASE),
            re.compile(r'id=["\']password["\']', re.IGNORECASE),
            re.compile(r'id=["\']passwd["\']', re.IGNORECASE),
            re.compile(r'id=["\']pass["\']', re.IGNORECASE),
            re.compile(r'id=["\']pwd["\']', re.IGNORECASE),
        ]

        # Login success/failure message patterns
        self.login_message_patterns = [
            re.compile(r'login failed', re.IGNORECASE),
            re.compile(r'invalid (password|credential)', re.IGNORECASE),
            re.compile(r'authentication failed', re.IGNORECASE),
            re.compile(r'incorrect password', re.IGNORECASE),
            re.compile(r'password incorrect', re.IGNORECASE),
            re.compile(r'access denied', re.IGNORECASE),
            re.compile(r'login successful', re.IGNORECASE),
            re.compile(r'successfully logged in', re.IGNORECASE),
            re.compile(r'successfully authenticated', re.IGNORECASE)
        ]

        # URL patterns with potential credentials - FILTERED for ACTUAL passwords
        self.url_with_creds_patterns = [
            re.compile(r'[?&]password=([^&]+)', re.IGNORECASE),
            re.compile(r'[?&]passwd=([^&]+)', re.IGNORECASE),
            re.compile(r'[?&]pass=([^&]+)', re.IGNORECASE),
            re.compile(r'[?&]pwd=([^&]+)', re.IGNORECASE),
        ]

        # Credential file patterns
        self.credential_file_patterns = [
            re.compile(r'credential', re.IGNORECASE),
            re.compile(r'password', re.IGNORECASE),
            re.compile(r'login', re.IGNORECASE),
            re.compile(r'auth', re.IGNORECASE),
            re.compile(r'\.key$', re.IGNORECASE),
            re.compile(r'\.cred$', re.IGNORECASE),
            re.compile(r'\.pem$', re.IGNORECASE)
        ]

        # Potential credential files
        self.potential_credentials = []
        self.ctf_flags = set()
        self.login_attempts = []
        self.credential_files = []
        self.token_strings = []
        self.password_fields = []
        self.decoded_data = []

        logger.info(f"Password extractor initialized with input dir: {input_dir}, output dir: {output_dir}")
        logger.info(f"CTF focus: {ctf_focus}")

    def scan_csv_files(self, max_files: int = 0) -> List[Path]:
        """
        Find all CSV files in the input directory.

        Args:
            max_files: Maximum number of files to process (0 = all files)

        Returns:
            List of file paths to process
        """
        csv_files = list(self.input_dir.glob("**/*.csv"))

        if max_files > 0 and len(csv_files) > max_files:
            csv_files = csv_files[:max_files]

        logger.info(f"Found {len(csv_files)} CSV files to process")
        return csv_files

    def extract_from_processed_data(self) -> Dict[str, Any]:
        """
        Extract credentials from already processed data in analysis directories.

        Returns:
            Dictionary with extraction results
        """
        results = {
            'potential_credentials': [],
            'ctf_flags': [],
            'login_attempts': [],
            'credential_files': [],
            'token_strings': [],
            'password_fields': []
        }

        # Look for analysis directories
        analysis_dirs = list(self.input_dir.glob("**/credential_analysis*")) + list(self.input_dir.glob("**/analysis*"))

        if not analysis_dirs:
            logger.warning("No analysis directories found. Will process CSV files directly.")
            return results

        for analysis_dir in analysis_dirs:
            logger.info(f"Checking analysis directory: {analysis_dir}")

            # Check for URLs file (likely contains form submissions)
            urls_files = list(analysis_dir.glob("**/urls_*.csv"))
            for urls_file in urls_files:
                self._process_urls_file(urls_file)

            # Check for login data files
            login_files = list(analysis_dir.glob("**/login_data_*.csv"))
            for login_file in login_files:
                self._process_login_data_file(login_file)

            # Check for autofill data
            autofill_files = list(analysis_dir.glob("**/autofill_*.csv"))
            for autofill_file in autofill_files:
                self._process_autofill_file(autofill_file)

            # Check for JSON analysis results
            json_files = list(analysis_dir.glob("**/*.json"))
            for json_file in json_files:
                self._process_json_file(json_file)

        # Update results
        results['potential_credentials'] = self.potential_credentials
        results['ctf_flags'] = self.ctf_flags
        results['login_attempts'] = self.login_attempts
        results['credential_files'] = self.credential_files
        results['token_strings'] = self.token_strings
        results['password_fields'] = self.password_fields

        return results

    def extract_from_raw_data(self, csv_files: List[Path]) -> Dict[str, Any]:
        """Extract passwords and CTF flags from raw CSV files.

        Args:
            csv_files: List of CSV files to process

        Returns:
            Dictionary with extracted data
        """
        for file_path in csv_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    row_count = 0

                    for row in reader:
                        row_count += 1
                        if row_count % 1000 == 0:
                            logger.debug(f"Processing row {row_count} in {file_path.name}")

                        # Skip rows with fewer than 2 columns
                        if len(row) < 2:
                            continue

                        # Join the row contents into a single string for pattern matching
                        row_content = " ".join(row)

                        try:
                            # Extract CTF flags
                            for pattern in self.ctf_flag_patterns:
                                matches = pattern.finditer(row_content)
                                for match in matches:
                                    self.ctf_flags.add(match.group(0))

                            # Check for URLs
                            url_pattern = re.compile(r'https?://[^\s]+')
                            url_matches = url_pattern.finditer(row_content)

                            for match in url_matches:
                                url = match.group(0)
                                self._extract_credentials_from_url(url)

                            # Check for possible POST data
                            if "POST" in row_content and "Content-Type: application/x-www-form-urlencoded" in row_content:
                                # Extract URL and message
                                url_match = url_pattern.search(row_content)
                                url = url_match.group(0) if url_match else ""

                                # Look for form data
                                self._extract_from_post_data(row_content, url)

                            # Look for login/password messages
                            for pattern in self.login_message_patterns:
                                if re.search(pattern, row_content):
                                    self.login_attempts.append({
                                        "message": row_content[:200],  # Truncate long messages
                                        "source": str(file_path)
                                    })
                                    break

                            # Generic message extraction
                            self._extract_from_message(row_content)

                            # Extract credential vault data
                            self._extract_credential_vault_data(row_content, str(file_path))
                        except Exception as row_error:
                            logger.error(f"Error processing row {row_count} in {file_path.name}: {row_error}")
                            import traceback
                            logger.debug(traceback.format_exc())

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                import traceback
                logger.debug(traceback.format_exc())

        # Prepare results
        results = {
            "ctf_flags": self.ctf_flags,
            "credentials": self.potential_credentials,
            "login_attempts": self.login_attempts,
            "token_strings": self.token_strings
        }

        return results

    def _process_urls_file(self, file_path: Path):
        """Process a URLs file from credential analysis output."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header row
                for row in reader:
                    if len(row) >= 3:  # Ensure row has enough fields
                        url = row[2]
                        self._extract_credentials_from_url(url)

                        # Extract CTF flags from URL
                        for pattern in self.ctf_flag_patterns:
                            matches = pattern.finditer(url)
                            for match in matches:
                                self.ctf_flags.add(match.group(0))

                        # Extract credential vault data
                        self._extract_credential_vault_data(url, str(file_path))
        except Exception as e:
            logger.error(f"Error processing URLs file {file_path}: {e}")

    def _process_login_data_file(self, file_path: Path):
        """Process a login data file from credential analysis output."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header row
                for row in reader:
                    if len(row) >= 5:  # Ensure row has enough fields
                        url = row[2]
                        username = row[3] if len(row) > 3 else ""
                        password = row[4] if len(row) > 4 else ""

                        if username and password:
                            # Mask password for security - show only length
                            masked_password = '*' * len(password)
                            self.credential_files.append({
                                'timestamp': row.get('timestamp', ''),
                                'path': url,
                                'message': f"{username} {masked_password} (length: {len(password)})",
                                'source': str(file_path)
                            })

                        # Extract CTF flags from all fields
                        content = " ".join(row)
                        for pattern in self.ctf_flag_patterns:
                            matches = pattern.finditer(content)
                            for match in matches:
                                self.ctf_flags.add(match.group(0))

                        # Extract credential vault data
                        self._extract_credential_vault_data(content, str(file_path))
        except Exception as e:
            logger.error(f"Error processing login data file {file_path}: {e}")

    def _process_autofill_file(self, file_path: Path):
        """Process an autofill data file from credential analysis output."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Extract potential credentials from form fields
                form_patterns = [
                    (r'name="(username|email|login)"[^>]*value="([^"]+)"', r'name="(password|passwd|pwd)"[^>]*value="([^"]+)"'),
                    (r'name="(username|email|login)"[^>]*value=\'([^\']+)\'', r'name="(password|passwd|pwd)"[^>]*value=\'([^\']+)\''),
                ]

                for user_pattern, pass_pattern in form_patterns:
                    user_matches = re.finditer(user_pattern, content, re.IGNORECASE)
                    pass_matches = re.finditer(pass_pattern, content, re.IGNORECASE)

                    user_values = [(m.group(2), m.start()) for m in user_matches]
                    pass_values = [(m.group(2), m.start()) for m in pass_matches]

                    # Match username/password pairs by proximity
                    for (username, user_pos) in user_values:
                        closest_pass = None
                        min_distance = float('inf')

                        for (password, pass_pos) in pass_values:
                            distance = abs(user_pos - pass_pos)
                            if distance < min_distance:
                                min_distance = distance
                                closest_pass = password

                        if closest_pass and min_distance < 1000:  # Only match if reasonably close
                            # Mask password for security - show only length
                            masked_password = '*' * len(closest_pass)
                            self.password_fields.append({
                                'timestamp': '',
                                'message': f"{username} {masked_password} (length: {len(closest_pass)})",
                                'source': str(file_path)
                            })

                # Extract CTF flags
                for pattern in self.ctf_flag_patterns:
                    matches = pattern.finditer(content)
                    for match in matches:
                        self.ctf_flags.add(match.group(0))

                # Extract credential vault data
                self._extract_credential_vault_data(content, str(file_path))
        except Exception as e:
            logger.error(f"Error processing autofill file {file_path}: {e}")

    def _process_json_file(self, file_path: Path):
        """Process a JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Try to parse JSON
                try:
                    data = json.loads(content)

                    # Extract from nested JSON objects
                    self._extract_from_json(data)
                except json.JSONDecodeError:
                    # If not valid JSON, process as text
                    pass

                # Always process content as text too
                for pattern in self.ctf_flag_patterns:
                    matches = pattern.finditer(content)
                    for match in matches:
                        self.ctf_flags.add(match.group(0))

                # Look for credentials in text
                self._extract_from_message(content)

                # Extract credential vault data
                self._extract_credential_vault_data(content, str(file_path))
        except Exception as e:
            logger.error(f"Error processing JSON file {file_path}: {e}")

    def _extract_credentials_from_url(self, url: str):
        """Extract potential credentials from a URL."""
        if not isinstance(url, str) or not url:
            return

        # Check for CTF flags in URL
        for pattern in self.ctf_flag_patterns:
            matches = pattern.findall(url)
            for match in matches:
                if match not in self.ctf_flags:
                    self.ctf_flags.add(match)

        # Check for credentials in URL parameters
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            # First check if this URL contains excluded token patterns
            url_lower = url.lower()
            for exclusion_pattern in self.token_exclusion_patterns:
                if exclusion_pattern.search(url_lower):
                    # Skip this URL as it contains an authentication token pattern
                    return

            # Look for password-related parameters
            for param, values in query_params.items():
                param_lower = param.lower()
                if any(pattern.search(param_lower) for pattern in self.password_field_patterns):
                    # Check this isn't a token pattern
                    if any(exclusion.search(param_lower) for exclusion in self.token_exclusion_patterns):
                        continue

                    for value in values:
                        if value and len(value) > 3:  # Filter out very short values
                            self.potential_credentials.append({
                                'source': 'url_parameter',
                                'url': url,
                                'parameter': param,
                                'value': value
                            })

            # Check for credentials in URL path
            for pattern in self.url_with_creds_patterns:
                for match in pattern.finditer(url):
                    # Safely extract group(1) if it exists
                    value = match.group(1) if match.lastindex is not None and match.lastindex >= 1 else ""
                    if value and isinstance(value, str) and len(value) > 3:
                        self.potential_credentials.append({
                            'source': 'url_parameter',
                            'url': url,
                            'parameter': match.group(0).split('=')[0],
                            'value': value
                        })
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            import traceback
            logger.debug(traceback.format_exc())

    def _extract_from_form_url(self, url: str):
        """Extract potential credentials from a form submission URL."""
        if not isinstance(url, str) or not url:
            return

        # First check if this URL contains excluded token patterns
        url_lower = url.lower()
        for exclusion_pattern in self.token_exclusion_patterns:
            if exclusion_pattern.search(url_lower):
                # Skip this URL as it contains an authentication token pattern
                return

        # Parse form data from URL
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        for param, values in query_params.items():
            param_lower = param.lower()

            # Check if this is a password-related parameter (not a token)
            if any(pattern.search(param_lower) for pattern in self.password_field_patterns) and \
               not any(exclusion.search(param_lower) for exclusion in self.token_exclusion_patterns):
                for value in values:
                    if value and len(value) > 3:
                        self.potential_credentials.append({
                            'source': 'form_submission',
                            'url': url,
                            'parameter': param,
                            'value': value
                        })

    def _extract_from_post_data(self, message: str, url: str):
        """Extract potential credentials from POST request data."""
        if not isinstance(message, str) or not message:
            return

        # Check for tokens in URL - if present, this is likely a token-based auth, not password
        url_lower = url.lower()
        for exclusion_pattern in self.token_exclusion_patterns:
            if exclusion_pattern.search(url_lower):
                # Skip this URL as it contains an authentication token pattern
                return

        # Look for form data sections
        form_data_match = re.search(r'Form data:(.+)', message, re.DOTALL | re.IGNORECASE)
        if form_data_match:
            form_data = form_data_match.group(1)

            # Extract key-value pairs
            pairs = re.findall(r'([^=&]+)=([^&]+)', form_data)

            # Check if we have both username and password fields (typical login form)
            has_username = False
            has_password = False

            for key, _ in pairs:
                key_lower = key.lower()
                if key_lower in ['username', 'user', 'email', 'login', 'loginid']:
                    has_username = True
                elif any(pattern.search(key_lower) for pattern in self.password_field_patterns):
                    has_password = True

            # Only process if this looks like a login form with both username and password
            if has_username and has_password:
                for key, value in pairs:
                    key_lower = key.lower()

                    # Check if this is a password-related field
                    if any(pattern.search(key_lower) for pattern in self.password_field_patterns) and \
                       not any(exclusion.search(key_lower) for exclusion in self.token_exclusion_patterns):
                        try:
                            # Try to decode URL-encoded value
                            decoded_value = urllib.parse.unquote_plus(value)
                            if decoded_value and len(decoded_value) > 3:
                                self.potential_credentials.append({
                                    'source': 'post_data',
                                    'url': url,
                                    'parameter': key,
                                    'value': decoded_value
                                })
                        except Exception:
                            # If decoding fails, use the raw value
                            if value and len(value) > 3:
                                self.potential_credentials.append({
                                    'source': 'post_data',
                                    'url': url,
                                    'parameter': key,
                                    'value': value
                                })

    def _extract_from_message(self, message: str):
        """Extract potential credentials from a message string."""
        if not isinstance(message, str) or not message:
            return

        # Check for login-related messages
        for pattern in self.login_message_patterns:
            if pattern.search(message):
                self.login_attempts.append({
                    'message': message,
                    'pattern': pattern.pattern
                })

        # Check for potential tokens or encoded credentials
        for pattern in self.encoded_patterns:
            matches = pattern.findall(message)
            for match in matches:
                # Try to decode as Base64
                try:
                    # Only consider strings that could be valid base64
                    if len(match) % 4 == 0 or match.endswith('=') or match.endswith('=='):
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')

                        # Check if the decoded string looks like printable text
                        if all(31 < ord(c) < 127 for c in decoded):
                            self.token_strings.append({
                                'encoded': match,
                                'decoded': decoded,
                                'source': 'base64'
                            })
                except Exception:
                    # If decoding fails, just store the raw token
                    self.token_strings.append({
                        'encoded': match,
                        'decoded': None,
                        'source': 'potential_token'
                    })

    def _extract_from_messages(self, messages: List[str]):
        """Extract potential credentials from a list of messages."""
        for message in messages:
            self._extract_from_message(message)

    def _extract_from_urls(self, urls: List[str]):
        """Extract potential credentials from a list of URLs."""
        for url in urls:
            self._extract_credentials_from_url(url)

    def _extract_from_form_data(self, form_data: List[str]):
        """Extract potential credentials from a list of form data strings."""
        for data in form_data:
            if isinstance(data, str) and data:
                # Check if this form data contains token patterns - if so, skip
                data_lower = data.lower()
                if any(exclusion.search(data_lower) for exclusion in self.token_exclusion_patterns):
                    continue

                # Look for key-value pairs
                pairs = re.findall(r'([^=&]+)=([^&]+)', data)

                # Check if we have both username and password fields (typical login form)
                has_username = False
                has_password = False

                for key, _ in pairs:
                    key_lower = key.lower()
                    if key_lower in ['username', 'user', 'email', 'login', 'loginid']:
                        has_username = True
                    elif any(pattern.search(key_lower) for pattern in self.password_field_patterns):
                        has_password = True

                # Only process if this looks like a login form with both username and password
                if has_username and has_password:
                    for key, value in pairs:
                        key_lower = key.lower()

                        # Check if this is a password-related field
                        if any(pattern.search(key_lower) for pattern in self.password_field_patterns) and \
                           not any(exclusion.search(key_lower) for exclusion in self.token_exclusion_patterns):
                            try:
                                # Try to decode URL-encoded value
                                decoded_value = urllib.parse.unquote_plus(value)
                                if decoded_value and len(decoded_value) > 3:
                                    self.potential_credentials.append({
                                        'source': 'form_data',
                                        'parameter': key,
                                        'value': decoded_value
                                    })
                            except Exception:
                                # If decoding fails, use the raw value
                                if value and len(value) > 3:
                                    self.potential_credentials.append({
                                        'source': 'form_data',
                                        'parameter': key,
                                        'value': value
                                    })

    def _extract_from_sources(self, sources: List[str]):
        """Extract potential credential files from a list of source strings."""
        for source in sources:
            if isinstance(source, str) and source:
                # Check if this source references a credential file
                for pattern in self.credential_file_patterns:
                    if pattern.search(source):
                        self.credential_files.append({
                            'source': source,
                            'pattern': pattern.pattern
                        })

    def export_results(self, results: Dict[str, Any]) -> Dict[str, str]:
        """
        Export extraction results to output files.

        Args:
            results: Dictionary with extraction results

        Returns:
            Dictionary with output file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_files = {}

        # Export CTF flags
        if results['ctf_flags']:
            ctf_flags_file = self.output_dir / f"ctf_flags_{timestamp}.txt"
            with open(ctf_flags_file, 'w') as f:
                for flag in results['ctf_flags']:
                    f.write(f"{flag}\n")
            output_files['ctf_flags'] = str(ctf_flags_file)

        # Export potential credentials
        if results['potential_credentials']:
            creds_file = self.output_dir / f"potential_credentials_{timestamp}.csv"
            with open(creds_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['source', 'parameter', 'value', 'url'])
                writer.writeheader()
                for cred in results['potential_credentials']:
                    writer.writerow({
                        'source': cred.get('source', ''),
                        'parameter': cred.get('parameter', ''),
                        'value': cred.get('value', ''),
                        'url': cred.get('url', '')
                    })
            output_files['credentials'] = str(creds_file)

        # Export token strings
        if results['token_strings']:
            tokens_file = self.output_dir / f"token_strings_{timestamp}.csv"
            with open(tokens_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['encoded', 'decoded', 'source'])
                writer.writeheader()
                for token in results['token_strings']:
                    writer.writerow({
                        'encoded': token.get('encoded', ''),
                        'decoded': token.get('decoded', ''),
                        'source': token.get('source', '')
                    })
            output_files['tokens'] = str(tokens_file)

        # Export credential files
        if results['credential_files']:
            cred_files_file = self.output_dir / f"credential_files_{timestamp}.csv"
            with open(cred_files_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'path', 'message', 'source', 'pattern'])
                writer.writeheader()
                for cred_file in results['credential_files']:
                    writer.writerow({
                        'timestamp': cred_file.get('timestamp', ''),
                        'path': cred_file.get('path', ''),
                        'message': cred_file.get('message', ''),
                        'source': cred_file.get('source', ''),
                        'pattern': cred_file.get('pattern', '')
                    })
            output_files['credential_files'] = str(cred_files_file)

        # Export password fields
        if results['password_fields']:
            fields_file = self.output_dir / f"password_fields_{timestamp}.csv"
            with open(fields_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'message', 'source'])
                writer.writeheader()
                for field in results['password_fields']:
                    writer.writerow({
                        'timestamp': field.get('timestamp', ''),
                        'message': field.get('message', ''),
                        'source': field.get('source', '')
                    })
            output_files['password_fields'] = str(fields_file)

        # Export login messages
        if results['login_attempts']:
            login_file = self.output_dir / f"login_messages_{timestamp}.csv"
            with open(login_file, 'w', encoding='utf-8', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Message', 'Source'])
                for message in results['login_attempts']:
                    writer.writerow([message.get('message', ''), message.get('source', '')])
            output_files['login_attempts'] = str(login_file)

        # Generate summary report
        summary_file = self.output_dir / f"password_extraction_summary_{timestamp}.md"
        with open(summary_file, 'w') as f:
            f.write("# Password Extraction Summary\n\n")
            f.write(f"Analysis performed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## Summary Statistics\n\n")
            f.write(f"- CTF Flags found: {len(results['ctf_flags'])}\n")
            f.write(f"- Potential credentials found: {len(results['potential_credentials'])}\n")
            f.write(f"- Token strings found: {len(results['token_strings'])}\n")
            f.write(f"- Credential files identified: {len(results['credential_files'])}\n")
            f.write(f"- Password fields detected: {len(results['password_fields'])}\n")
            f.write(f"- Login attempts found: {len(results['login_attempts'])}\n\n")

            # Write CTF flags
            if results['ctf_flags']:
                f.write("## CTF Flags\n\n")
                for flag in results['ctf_flags']:
                    f.write(f"- `{flag}`\n")
                f.write("\n")

            # Write top potential credentials
            if results['potential_credentials']:
                f.write("## Top Potential Credentials\n\n")
                f.write("| Source | Parameter | Value | URL |\n")
                f.write("|--------|-----------|-------|-----|\n")

                # Show top 20 credentials
                for cred in results['potential_credentials'][:20]:
                    source = cred.get('source', '')
                    param = cred.get('parameter', '')
                    value = cred.get('value', '')
                    url = cred.get('url', '')

                    # Truncate long values
                    if len(value) > 50:
                        value = value[:47] + "..."
                    if url and len(url) > 50:
                        url = url[:47] + "..."

                    f.write(f"| {source} | {param} | `{value}` | {url} |\n")

                if len(results['potential_credentials']) > 20:
                    f.write(f"\n*Note: {len(results['potential_credentials']) - 20} more credentials found.*\n\n")
                else:
                    f.write("\n")

            # Write decoded tokens
            if results['token_strings']:
                decoded_tokens = [t for t in results['token_strings'] if t.get('decoded')]
                if decoded_tokens:
                    f.write("## Decoded Tokens\n\n")
                    f.write("| Encoded | Decoded | Source |\n")
                    f.write("|---------|---------|--------|\n")

                    # Show top 10 decoded tokens
                    for token in decoded_tokens[:10]:
                        encoded = token.get('encoded', '')
                        decoded = token.get('decoded', '')
                        source = token.get('source', '')

                        # Truncate long values
                        if len(encoded) > 20:
                            encoded = encoded[:17] + "..."
                        if len(decoded) > 30:
                            decoded = decoded[:27] + "..."

                        f.write(f"| `{encoded}` | `{decoded}` | {source} |\n")

                    if len(decoded_tokens) > 10:
                        f.write(f"\n*Note: {len(decoded_tokens) - 10} more decoded tokens found.*\n\n")
                    else:
                        f.write("\n")

            # List credential files
            if results['credential_files']:
                f.write("## Credential Files\n\n")
                # Show top 10 credential files
                for i, cred_file in enumerate(results['credential_files'][:10]):
                    path = cred_file.get('path', cred_file.get('source', ''))
                    f.write(f"{i+1}. {path}\n")

                if len(results['credential_files']) > 10:
                    f.write(f"\n*Note: {len(results['credential_files']) - 10} more credential files identified.*\n\n")
                else:
                    f.write("\n")

        output_files['summary'] = str(summary_file)
        return output_files

    def run_extraction(self, max_files: int = 0) -> Dict[str, str]:
        """
        Run the credential extraction process.

        Args:
            max_files: Maximum number of files to process (0 = all files)

        Returns:
            Dictionary with output file paths
        """
        # First try to extract from processed data
        logger.info("Attempting to extract from processed analysis data...")
        results = self.extract_from_processed_data()

        # If no processed data is found or it's empty, try raw data
        if (not results['potential_credentials'] and not results['ctf_flags'] and
            not results['credential_files'] and not results['token_strings']):
            logger.info("No results from processed data, trying raw CSV files...")
            csv_files = self.scan_csv_files(max_files)
            results = self.extract_from_raw_data(csv_files)

        # Export results
        logger.info("Exporting extraction results...")
        output_files = self.export_results(results)

        # Log summary
        logger.info(f"Extraction complete! Found:")
        logger.info(f"- {len(results['ctf_flags'])} CTF flags")
        logger.info(f"- {len(results['potential_credentials'])} potential credentials")
        logger.info(f"- {len(results['token_strings'])} token strings")
        logger.info(f"- {len(results['credential_files'])} credential files")
        logger.info(f"- {len(results['password_fields'])} password fields")
        logger.info(f"- {len(results['login_attempts'])} login attempts")

        return output_files

    def _extract_credential_vault_data(self, content: str, source: str) -> None:
        """
        Extract credential vault data from content.

        Args:
            content: The text content to analyze
            source: The source of the content for reference
        """
        try:
            # Check for Windows Credential Vault entries
            credential_patterns = [
                # Regular Credential Vault entry
                re.compile(r'Credential\s+:\s+([^\n]+)', re.IGNORECASE),
                # Target info
                re.compile(r'TargetName\s+:\s+([^\n]+)', re.IGNORECASE),
                # SyncCredential entries
                re.compile(r'SyncCredential\{([^}]+)\}', re.IGNORECASE),
                # Password entries
                re.compile(r'Password\{([^}]+)\}', re.IGNORECASE),
                # Generic credentials with target information
                re.compile(r'Credential\s+for\s+(.+?)\s*[:-]\s*(.+)', re.IGNORECASE)
            ]

            for pattern in credential_patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    logger.debug(f"Found credential match: {match.group(0)}")
                    logger.debug(f"Match groups: {match.groups()}")
                    logger.debug(f"Match lastindex: {match.lastindex}")

                    if pattern.pattern == r'Credential\s+for\s+(.+?)\s*[:-]\s*(.+)':
                        # For credential with target pattern
                        target = match.group(1) if match.lastindex and match.lastindex >= 1 else "Unknown"
                        credential = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                    elif pattern.pattern in [r'SyncCredential\{([^}]+)\}', r'Password\{([^}]+)\}']:
                        # For SyncCredential and Password patterns
                        target = pattern.pattern.split(r'\{')[0]
                        credential = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    else:
                        # For other patterns
                        target = "Credential Vault Entry"
                        credential = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

                    self.potential_credentials.append({
                        "username": target,
                        "password": credential,
                        "url": "windows-credential-vault",
                        "source": source
                    })

                    # Also add to tokens for further analysis
                    self.token_strings.append({
                        "token": credential,
                        "context": f"Windows Credential: {target}",
                        "source": source,
                        "decoded": None
                    })
        except Exception as e:
            logger.error(f"Error in _extract_credential_vault_data: {e}")
            import traceback
            logger.debug(traceback.format_exc())

    def process_files(self, max_files: Optional[int] = None, raw_files: bool = False, verbose: bool = False) -> None:
        """Process all files in the input directory.

        Args:
            max_files: Maximum number of files to process (None = all files)
            raw_files: If True, process raw CSV files directly rather than credential analysis output
            verbose: If True, print verbose output
        """
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            logging.getLogger().setLevel(logging.INFO)

        logger.info(f"Processing files from {self.input_dir}")
        logger.info(f"Output will be saved to {self.output_dir}")

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        if raw_files:
            # Process raw CSV files directly
            csv_files = []
            for root, _, files in os.walk(self.input_dir):
                for file in files:
                    if file.endswith('.csv'):
                        csv_files.append(Path(os.path.join(root, file)))

            if max_files is not None and max_files > 0:
                csv_files = csv_files[:max_files]

            logger.info(f"Found {len(csv_files)} CSV files, processing...")
            self.extract_from_raw_data(csv_files)
        else:
            # Process credential analysis output
            logger.info("Processing credential analysis output...")
            self.extract_from_processed_data()

        logger.info("Processing complete!")

    def export_results(self) -> None:
        """Export the extraction results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Ensure output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Export CTF flags
        if self.ctf_flags:
            ctf_flags_file = os.path.join(self.output_dir, f"ctf_flags_{timestamp}.txt")
            with open(ctf_flags_file, 'w', encoding='utf-8') as file:
                for flag in sorted(self.ctf_flags):
                    file.write(f"{flag}\n")
            logger.info(f"CTF flags saved to: {ctf_flags_file}")

        # Export potential credentials
        if self.potential_credentials:
            credentials_file = os.path.join(self.output_dir, f"potential_credentials_{timestamp}.csv")
            with open(credentials_file, 'w', encoding='utf-8', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Username', 'Password', 'URL', 'Source', 'Type'])
                for cred in self.potential_credentials:
                    # Mask password for security
                    password = cred.get('password', '')
                    masked_password = '*' * len(password) + f' (length: {len(password)})' if password else ''
                    writer.writerow([
                        cred.get('username', ''),
                        masked_password,
                        cred.get('url', ''),
                        cred.get('source', ''),
                        cred.get('type', '')
                    ])
            logger.info(f"Potential credentials saved to: {credentials_file}")

        # Export login messages
        if self.login_attempts:
            login_file = os.path.join(self.output_dir, f"login_messages_{timestamp}.csv")
            with open(login_file, 'w', encoding='utf-8', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Message', 'Source'])
                for message in self.login_attempts:
                    writer.writerow([message.get('message', ''), message.get('source', '')])
            logger.info(f"Login messages saved to: {login_file}")

        # Export tokens
        if self.token_strings:
            tokens_file = os.path.join(self.output_dir, f"token_strings_{timestamp}.csv")
            with open(tokens_file, 'w', encoding='utf-8', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Token', 'Type', 'Source'])
                for token in self.token_strings:
                    writer.writerow([token.get('token', ''), token.get('type', ''), token.get('source', '')])
            logger.info(f"Token strings saved to: {tokens_file}")

        # Export credential files
        if self.credential_files:
            credential_files_file = os.path.join(self.output_dir, f"credential_files_{timestamp}.csv")
            with open(credential_files_file, 'w', encoding='utf-8', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Path', 'Message', 'Source'])
                for cred_file in self.credential_files:
                    writer.writerow([
                        cred_file.get('timestamp', ''),
                        cred_file.get('path', ''),
                        cred_file.get('message', ''),
                        cred_file.get('source', '')
                    ])
            logger.info(f"Credential files saved to: {credential_files_file}")

        # Export password fields
        if self.password_fields:
            password_fields_file = os.path.join(self.output_dir, f"password_fields_{timestamp}.csv")
            with open(password_fields_file, 'w', encoding='utf-8', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Message', 'Source'])
                for field in self.password_fields:
                    writer.writerow([field.get('timestamp', ''), field.get('message', ''), field.get('source', '')])
            logger.info(f"Password fields saved to: {password_fields_file}")

        # Create a summary file
        summary_file = os.path.join(self.output_dir, f"password_extraction_summary_{timestamp}.md")
        with open(summary_file, 'w', encoding='utf-8') as file:
            file.write("# Password Extraction Summary\n\n")
            file.write(f"Analysis performed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            file.write("## Summary Statistics\n\n")
            file.write(f"- CTF Flags found: {len(self.ctf_flags)}\n")
            file.write(f"- Potential credentials found: {len(self.potential_credentials)}\n")
            file.write(f"- Token strings found: {len(self.token_strings)}\n")
            file.write(f"- Credential files identified: {len(self.credential_files)}\n")
            file.write(f"- Password fields detected: {len(self.password_fields)}\n")
            file.write(f"- Login attempts found: {len(self.login_attempts)}\n\n")

            if self.ctf_flags:
                file.write("## CTF Flags\n\n")
                for flag in sorted(self.ctf_flags):
                    file.write(f"- `{flag}`\n")
                file.write("\n")

            if self.potential_credentials:
                file.write("## Top Potential Credentials\n\n")
                file.write("| Username | Password | Source | Type |\n")
                file.write("|----------|----------|--------|------|\n")
                for cred in self.potential_credentials[:10]:  # Show top 10
                    # Do not store any password or its length
                    file.write(f"| {cred.get('username', '')} | [REDACTED] | {cred.get('source', '')} | {cred.get('type', '')} |\n")
                if len(self.potential_credentials) > 10:
                    file.write(f"\n*Note: {len(self.potential_credentials) - 10} more credentials found.*\n\n")
                else:
                    file.write("\n")

            if self.decoded_data:
                file.write("## Decoded Tokens\n\n")
                file.write("| Encoded | Decoded | Source |\n")
                file.write("|---------|---------|--------|\n")
                for data in self.decoded_data[:10]:  # Show top 10
                    encoded = data.get('encoded', '')[:30] + ('...' if len(data.get('encoded', '')) > 30 else '')
                    decoded = data.get('decoded', '')[:30] + ('...' if len(data.get('decoded', '')) > 30 else '')
                    file.write(f"| `{encoded}` | `{decoded}` | {data.get('source', '')} |\n")

                if len(self.decoded_data) > 10:
                    file.write(f"\n*Note: {len(self.decoded_data) - 10} more decoded tokens found.*\n")

        logger.info(f"Summary report available at: {summary_file}")

def main():
    """Main entry point for the password extractor."""
    parser = argparse.ArgumentParser(description='Extract passwords and CTF flags from browser forensic data.')
    parser.add_argument('--input-dir', required=True, help='Directory containing input files to analyze')
    parser.add_argument('--output-dir', required=True, help='Directory where output will be saved')
    parser.add_argument('--max-files', type=int, help='Maximum number of files to process')
    parser.add_argument('--ctf-focus', action='store_true', help='Focus on extracting CTF flags')
    parser.add_argument('--raw-files', action='store_true', help='Process raw CSV files directly')
    parser.add_argument('--verbose', action='store_true', help='Print verbose output')

    args = parser.parse_args()

    extractor = PasswordExtractor(args.input_dir, args.output_dir, args.ctf_focus)
    extractor.process_files(args.max_files, args.raw_files, args.verbose)
    extractor.export_results()

    return 0


if __name__ == "__main__":
    sys.exit(main())