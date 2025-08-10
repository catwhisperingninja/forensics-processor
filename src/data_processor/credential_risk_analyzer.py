#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Credential Risk Analyzer for Browser Forensics Data
This module performs risk analysis on credential-related data extracted from browser forensic files.
"""

import os
import re
import json
import logging
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set, Optional
from datetime import datetime, timedelta
import networkx as nx
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import numpy as np

# Import the base credential analyzer
from data_processor.credential_analyzer import CredentialAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CredentialRiskAnalyzer:
    """Analyze security risks in browser credential and autofill data."""

    def __init__(self, analysis_dir: str, output_dir: Optional[str] = None):
        """
        Initialize the risk analyzer.

        Args:
            analysis_dir: Directory containing credential analysis results
            output_dir: Directory where risk analysis results will be saved (defaults to analysis_dir/risk_analysis)
        """
        self.analysis_dir = Path(analysis_dir)

        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = self.analysis_dir / "risk_analysis"

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Data files
        self.login_data_file = self.analysis_dir / "login_data_*.csv"
        self.autofill_file = self.analysis_dir / "autofill_*.csv"
        self.extensions_file = self.analysis_dir / "extensions_*.csv"
        self.urls_file = self.analysis_dir / "urls_*.csv"
        self.cookies_file = self.analysis_dir / "cookies_*.csv"

        # Risk scoring parameters
        self.risk_thresholds = {
            "high": 8,
            "medium": 5,
            "low": 3
        }

        # Security risk patterns
        self.suspicious_patterns = {
            'password_reset': re.compile(r'reset|forgot|recover', re.IGNORECASE),
            'account_creation': re.compile(r'signup|register|create account', re.IGNORECASE),
            'sensitive_data': re.compile(r'ssn|social security|passport|license|credit.{1,5}card|tax', re.IGNORECASE),
            'financial': re.compile(r'bank|finance|payment|wallet|crypto|bitcoin', re.IGNORECASE),
            'corporate': re.compile(r'admin|dashboard|portal|internal', re.IGNORECASE)
        }

        # Known malicious patterns
        self.malicious_patterns = {
            'phishing': re.compile(r'signin|login|account.*?\.(?!com|org|net|gov|edu|co\.uk|io)', re.IGNORECASE),
            'suspicious_domains': re.compile(r'bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd', re.IGNORECASE),
            'data_exfil': re.compile(r'pastebin\.com|transfer\.sh|mega\.nz|anonfiles', re.IGNORECASE)
        }

        # Risk factors for different artifact types
        self.artifact_risk_factors = {
            'login_data': 2.0,  # Highest risk
            'autofill': 1.5,    # Medium-high risk
            'cookies': 1.0,     # Medium risk
            'extensions': 0.5   # Lower risk
        }

    def _find_latest_file(self, pattern: str) -> Optional[Path]:
        """Find the most recent file matching a pattern."""
        files = list(self.analysis_dir.glob(pattern))
        if not files:
            return None
        return sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)[0]

    def load_analysis_data(self) -> Dict[str, pd.DataFrame]:
        """
        Load data from credential analysis output files.

        Returns:
            Dictionary of pandas DataFrames containing the analysis data
        """
        data = {}

        # Find the latest files of each type
        login_data_files = list(self.analysis_dir.glob("login_data_*.csv"))
        autofill_files = list(self.analysis_dir.glob("autofill_*.csv"))
        extensions_files = list(self.analysis_dir.glob("extensions_*.csv"))
        urls_files = list(self.analysis_dir.glob("urls_*.csv"))
        cookies_files = list(self.analysis_dir.glob("cookies_*.csv"))

        # Load data if files exist
        if login_data_files:
            latest_file = sorted(login_data_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
            data['login_data'] = pd.read_csv(latest_file)
            logger.info(f"Loaded login data from {latest_file}")

        if autofill_files:
            latest_file = sorted(autofill_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
            data['autofill'] = pd.read_csv(latest_file)
            logger.info(f"Loaded autofill data from {latest_file}")

        if extensions_files:
            latest_file = sorted(extensions_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
            data['extensions'] = pd.read_csv(latest_file)
            logger.info(f"Loaded extensions data from {latest_file}")

        if urls_files:
            latest_file = sorted(urls_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
            data['urls'] = pd.read_csv(latest_file)
            logger.info(f"Loaded URL data from {latest_file}")

        if cookies_files:
            latest_file = sorted(cookies_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
            data['cookies'] = pd.read_csv(latest_file)
            logger.info(f"Loaded cookie data from {latest_file}")

        # Also load URL analysis results if available
        url_analysis_files = list(self.analysis_dir.glob("url_analysis_*.json"))
        if url_analysis_files:
            latest_file = sorted(url_analysis_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
            with open(latest_file, 'r') as f:
                data['url_analysis'] = json.load(f)
            logger.info(f"Loaded URL analysis from {latest_file}")

        return data

    def analyze_password_reuse_risk(self, login_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Identify potential password reuse across different sites.

        Args:
            login_data: DataFrame containing login data information

        Returns:
            Dictionary of password reuse analysis
        """
        # In forensic data we don't have actual passwords, but we can analyze login patterns
        # by looking at timestamps and sequence of logins

        result = {
            'potential_reuse_patterns': [],
            'rapid_login_sequences': [],
            'risk_level': 'low'
        }

        if login_data.empty:
            return result

        # Check for login sequences in short time periods
        if 'timestamp' in login_data.columns:
            login_data['timestamp'] = pd.to_datetime(login_data['timestamp'])
            login_data = login_data.sort_values('timestamp')

            # Look for multiple logins within short time windows (5 minutes)
            time_threshold = timedelta(minutes=5)
            previous_time = None
            login_sequence = []

            for idx, row in login_data.iterrows():
                if previous_time is None:
                    previous_time = row['timestamp']
                    login_sequence = [row]
                else:
                    current_time = row['timestamp']
                    time_diff = current_time - previous_time

                    if time_diff <= time_threshold:
                        login_sequence.append(row)
                    else:
                        # If sequence has multiple logins, record it
                        if len(login_sequence) > 1:
                            result['rapid_login_sequences'].append({
                                'timestamp_start': login_sequence[0]['timestamp'].isoformat(),
                                'timestamp_end': login_sequence[-1]['timestamp'].isoformat(),
                                'sequence_length': len(login_sequence),
                                'files': [entry.get('path', '') for entry in login_sequence]
                            })

                        # Reset sequence
                        login_sequence = [row]

                    previous_time = current_time

            # Check final sequence
            if len(login_sequence) > 1:
                result['rapid_login_sequences'].append({
                    'timestamp_start': login_sequence[0]['timestamp'].isoformat(),
                    'timestamp_end': login_sequence[-1]['timestamp'].isoformat(),
                    'sequence_length': len(login_sequence),
                    'files': [entry.get('path', '') for entry in login_sequence]
                })

            # Set risk level based on number of rapid sequences
            if len(result['rapid_login_sequences']) > 5:
                result['risk_level'] = 'high'
            elif len(result['rapid_login_sequences']) > 2:
                result['risk_level'] = 'medium'

        return result

    def analyze_autofill_exposure(self, autofill_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze potential exposure of sensitive information through autofill.

        Args:
            autofill_data: DataFrame containing autofill information

        Returns:
            Dictionary of autofill risk analysis
        """
        result = {
            'sensitive_fields_count': 0,
            'high_risk_domains': [],
            'risk_level': 'low'
        }

        if autofill_data.empty:
            return result

        # Check for sensitive field patterns in messages
        if 'message' in autofill_data.columns:
            sensitive_patterns = [
                re.compile(r'credit.{1,5}card', re.IGNORECASE),
                re.compile(r'ssn|social', re.IGNORECASE),
                re.compile(r'passport', re.IGNORECASE),
                re.compile(r'address', re.IGNORECASE),
                re.compile(r'phone', re.IGNORECASE),
                re.compile(r'birth', re.IGNORECASE),
                re.compile(r'account.{1,5}number', re.IGNORECASE),
                re.compile(r'routing.{1,5}number', re.IGNORECASE)
            ]

            for idx, row in autofill_data.iterrows():
                message = row.get('message', '')

                for pattern in sensitive_patterns:
                    if pattern.search(message):
                        result['sensitive_fields_count'] += 1

                        # Extract domain if present
                        domain_match = re.search(r'https?://([^/]+)', message)
                        if domain_match:
                            domain = domain_match.group(1)
                            if domain not in result['high_risk_domains']:
                                result['high_risk_domains'].append(domain)

        # Set risk level based on sensitive field count
        if result['sensitive_fields_count'] > 10:
            result['risk_level'] = 'high'
        elif result['sensitive_fields_count'] > 5:
            result['risk_level'] = 'medium'

        return result

    def analyze_extension_risks(self, extensions_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze potential risks from browser extensions.

        Args:
            extensions_data: DataFrame containing extension information

        Returns:
            Dictionary of extension risk analysis
        """
        result = {
            'high_risk_extensions': [],
            'security_extensions': [],
            'total_extensions': 0,
            'risk_level': 'low'
        }

        if extensions_data.empty:
            return result

        # Count unique extensions by looking at paths
        if 'path' in extensions_data.columns:
            extension_paths = extensions_data['path'].tolist()
            unique_extensions = set()

            for path in extension_paths:
                # Skip non-string path values
                if not isinstance(path, str):
                    continue

                if not path:
                    continue

                # Extract extension ID from path
                ext_id_match = re.search(r'Extension[s]?[/\\]([a-zA-Z0-9]+)', path, re.IGNORECASE)
                if ext_id_match:
                    ext_id = ext_id_match.group(1)
                    unique_extensions.add(ext_id)

            result['total_extensions'] = len(unique_extensions)

            # Look for security-related extensions
            security_patterns = [
                re.compile(r'password|lastpass|1password|bitwarden|dashlane|keeper', re.IGNORECASE),
                re.compile(r'security|protect|adblocker|firewall|vpn', re.IGNORECASE),
                re.compile(r'privacy|tracker|blocker', re.IGNORECASE)
            ]

            # Look for potentially risky extensions
            risk_patterns = [
                re.compile(r'screen.{1,10}capture|screenshot', re.IGNORECASE),
                re.compile(r'keylog|recorder|monitor', re.IGNORECASE),
                re.compile(r'download|upload|transfer', re.IGNORECASE)
            ]

            for idx, row in extensions_data.iterrows():
                message = row.get('message', '')

                # Skip non-string message values
                if not isinstance(message, str):
                    continue

                for pattern in security_patterns:
                    if pattern.search(message) and message not in result['security_extensions']:
                        result['security_extensions'].append(message)

                for pattern in risk_patterns:
                    if pattern.search(message) and message not in result['high_risk_extensions']:
                        result['high_risk_extensions'].append(message)

        # Set risk level based on high risk extensions
        if len(result['high_risk_extensions']) > 2:
            result['risk_level'] = 'high'
        elif len(result['high_risk_extensions']) > 0:
            result['risk_level'] = 'medium'

        return result

    def analyze_login_temporal_patterns(self, urls_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze login activity patterns over time.

        Args:
            urls_data: DataFrame containing URL visit information

        Returns:
            Dictionary of temporal pattern analysis
        """
        result = {
            'unusual_hours_activity': [],
            'activity_bursts': [],
            'risk_level': 'low'
        }

        if urls_data.empty:
            return result

        # Filter for login/authentication URLs
        if 'url' in urls_data.columns:
            login_patterns = re.compile(r'login|signin|auth|account', re.IGNORECASE)
            login_urls = urls_data[urls_data['url'].str.contains(login_patterns, na=False)]

            if not login_urls.empty and 'timestamp' in login_urls.columns:
                login_urls['timestamp'] = pd.to_datetime(login_urls['timestamp'])
                login_urls = login_urls.sort_values('timestamp')

                # Analyze time of day patterns
                login_urls['hour'] = login_urls['timestamp'].dt.hour
                hour_counts = login_urls['hour'].value_counts()

                # Look for unusual hour activity (late night/early morning)
                unusual_hours = [0, 1, 2, 3, 4]
                for hour in unusual_hours:
                    if hour in hour_counts and hour_counts[hour] > 0:
                        result['unusual_hours_activity'].append({
                            'hour': hour,
                            'count': int(hour_counts[hour]),
                            'urls': login_urls[login_urls['hour'] == hour]['url'].unique().tolist()[:5]  # Limit to 5 examples
                        })

                # Look for unusual bursts of activity
                login_urls['date'] = login_urls['timestamp'].dt.date
                date_counts = login_urls['date'].value_counts()

                # Identify dates with significantly higher than average activity
                mean_logins = date_counts.mean()
                std_logins = date_counts.std()

                if not pd.isna(std_logins) and std_logins > 0:
                    threshold = mean_logins + 2 * std_logins  # 2 standard deviations above mean

                    for date, count in date_counts.items():
                        if count > threshold:
                            result['activity_bursts'].append({
                                'date': str(date),
                                'count': int(count),
                                'expected': int(mean_logins)
                            })

        # Set risk level based on unusual activity
        if len(result['unusual_hours_activity']) > 2 or len(result['activity_bursts']) > 1:
            result['risk_level'] = 'high'
        elif len(result['unusual_hours_activity']) > 0 or len(result['activity_bursts']) > 0:
            result['risk_level'] = 'medium'

        return result

    def generate_domain_network(self, urls_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate a network analysis of domains visited in sequence.

        Args:
            urls_data: DataFrame containing URL visit information

        Returns:
            Dictionary with network analysis results
        """
        result = {
            'high_centrality_domains': [],
            'unusual_transitions': [],
            'risk_level': 'low'
        }

        if urls_data.empty:
            return result

        # Create a directed graph of domain transitions
        if 'url' in urls_data.columns and 'timestamp' in urls_data.columns:
            # Extract domains from URLs
            urls_data['domain'] = urls_data['url'].apply(
                lambda url: re.search(r'https?://([^/]+)', url).group(1) if re.search(r'https?://([^/]+)', url) else ''
            )
            urls_data = urls_data[urls_data['domain'] != '']

            if len(urls_data) < 2:
                return result

            # Sort by timestamp
            urls_data['timestamp'] = pd.to_datetime(urls_data['timestamp'])
            urls_data = urls_data.sort_values('timestamp')

            # Create graph
            G = nx.DiGraph()

            # Add domain transitions as edges
            previous_domain = None
            for idx, row in urls_data.iterrows():
                current_domain = row['domain']

                if previous_domain is not None and previous_domain != current_domain:
                    if G.has_edge(previous_domain, current_domain):
                        G[previous_domain][current_domain]['weight'] += 1
                    else:
                        G.add_edge(previous_domain, current_domain, weight=1)

                previous_domain = current_domain

            # Calculate centrality
            if len(G.nodes()) > 0:
                centrality = nx.degree_centrality(G)
                eigenvector_centrality = {node: 0.0 for node in G.nodes()}

                try:
                    eigenvector_centrality = nx.eigenvector_centrality(G, max_iter=1000)
                except:
                    logger.warning("Eigenvector centrality calculation failed, using degree centrality only")

                # Combine centrality measures
                combined_centrality = {}
                for node in G.nodes():
                    combined_centrality[node] = centrality.get(node, 0) + eigenvector_centrality.get(node, 0)

                # Get high centrality domains
                sorted_domains = sorted(combined_centrality.items(), key=lambda x: x[1], reverse=True)
                result['high_centrality_domains'] = [{'domain': domain, 'centrality': float(score)}
                                                   for domain, score in sorted_domains[:10]]

                # Find unusual transitions (low weight edges between dissimilar domains)
                unusual_edges = []
                for u, v, data in G.edges(data=True):
                    weight = data.get('weight', 0)

                    # Simple heuristic: transitions with weight=1 between domains that don't share keywords
                    if weight <= 2:
                        u_parts = u.split('.')
                        v_parts = v.split('.')

                        similarity = len(set(u_parts) & set(v_parts))
                        if similarity == 0:  # No common elements
                            unusual_edges.append((u, v, weight))

                # Sort by weight and take top 20
                unusual_edges.sort(key=lambda x: x[2])
                result['unusual_transitions'] = [{'from': u, 'to': v, 'weight': w}
                                              for u, v, w in unusual_edges[:20]]

        # Set risk level based on unusual transitions
        if len(result['unusual_transitions']) > 10:
            result['risk_level'] = 'high'
        elif len(result['unusual_transitions']) > 5:
            result['risk_level'] = 'medium'

        return result

    def calculate_overall_risk_score(self, risk_analyses: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate an overall security risk score based on individual analyses.

        Args:
            risk_analyses: Dictionary of risk analysis results

        Returns:
            Dictionary with overall risk assessment
        """
        # Risk scoring weights for different analyses
        risk_weights = {
            'password_reuse': 0.25,
            'autofill_exposure': 0.20,
            'extension_risks': 0.15,
            'temporal_patterns': 0.20,
            'domain_network': 0.20
        }

        # Convert risk levels to scores
        risk_scores = {
            'high': 10,
            'medium': 5,
            'low': 1
        }

        # Calculate weighted score
        total_score = 0
        max_possible_score = 0

        for analysis_type, weight in risk_weights.items():
            if analysis_type in risk_analyses:
                risk_level = risk_analyses[analysis_type].get('risk_level', 'low')
                score = risk_scores.get(risk_level, 0)
                total_score += score * weight
                max_possible_score += 10 * weight

        # Normalize to 0-10 scale
        if max_possible_score > 0:
            normalized_score = (total_score / max_possible_score) * 10
        else:
            normalized_score = 0

        # Determine overall risk level
        if normalized_score >= self.risk_thresholds['high']:
            overall_risk = 'high'
        elif normalized_score >= self.risk_thresholds['medium']:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'

        # Compile risk factors
        risk_factors = []

        if 'password_reuse' in risk_analyses:
            rapid_sequences = risk_analyses['password_reuse'].get('rapid_login_sequences', [])
            if rapid_sequences:
                risk_factors.append(f"Detected {len(rapid_sequences)} instances of rapid login sequences across multiple sites")

        if 'autofill_exposure' in risk_analyses:
            sensitive_count = risk_analyses['autofill_exposure'].get('sensitive_fields_count', 0)
            if sensitive_count > 0:
                risk_factors.append(f"Found {sensitive_count} instances of potentially sensitive data in autofill")

        if 'extension_risks' in risk_analyses:
            high_risk_exts = risk_analyses['extension_risks'].get('high_risk_extensions', [])
            if high_risk_exts:
                risk_factors.append(f"Identified {len(high_risk_exts)} potentially high-risk browser extensions")

        if 'temporal_patterns' in risk_analyses:
            unusual_hours = risk_analyses['temporal_patterns'].get('unusual_hours_activity', [])
            if unusual_hours:
                risk_factors.append(f"Detected login activity during unusual hours ({len(unusual_hours)} instances)")

        if 'domain_network' in risk_analyses:
            unusual_transitions = risk_analyses['domain_network'].get('unusual_transitions', [])
            if unusual_transitions:
                risk_factors.append(f"Found {len(unusual_transitions)} unusual domain transitions in browsing patterns")

        return {
            'score': normalized_score,
            'risk_level': overall_risk,
            'risk_factors': risk_factors
        }

    def generate_risk_report(self, risk_analyses: Dict[str, Dict[str, Any]], overall_risk: Dict[str, Any]) -> str:
        """
        Generate a comprehensive risk report in Markdown format.

        Args:
            risk_analyses: Dictionary of risk analysis results
            overall_risk: Overall risk assessment

        Returns:
            Markdown formatted report
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = [
            "# Browser Security Risk Analysis Report",
            f"Analysis performed: {timestamp}",
            "",
            "## Executive Summary",
            f"Overall Security Risk: **{overall_risk['risk_level'].upper()}**",
            f"Risk Score: {overall_risk['score']:.1f}/10",
            "",
            "### Key Risk Factors"
        ]

        for factor in overall_risk['risk_factors']:
            report.append(f"- {factor}")

        if not overall_risk['risk_factors']:
            report.append("- No significant risk factors identified")

        # Password Reuse Analysis
        if 'password_reuse' in risk_analyses:
            analysis = risk_analyses['password_reuse']
            report.extend([
                "",
                "## Password Reuse Analysis",
                f"Risk Level: **{analysis['risk_level'].upper()}**",
                "",
                "### Rapid Login Sequences"
            ])

            if analysis['rapid_login_sequences']:
                for idx, sequence in enumerate(analysis['rapid_login_sequences'][:5]):  # Show top 5
                    report.extend([
                        f"#### Sequence {idx+1}",
                        f"- Time Range: {sequence['timestamp_start']} to {sequence['timestamp_end']}",
                        f"- Sequence Length: {sequence['sequence_length']} logins",
                        f"- Login Data Files: {', '.join(sequence['files'][:3])}{'...' if len(sequence['files']) > 3 else ''}"
                    ])
            else:
                report.append("No suspicious login sequences detected")

        # Autofill Exposure Analysis
        if 'autofill_exposure' in risk_analyses:
            analysis = risk_analyses['autofill_exposure']
            report.extend([
                "",
                "## Autofill Data Exposure Analysis",
                f"Risk Level: **{analysis['risk_level'].upper()}**",
                f"Sensitive Fields Count: {analysis['sensitive_fields_count']}",
                "",
                "### High Risk Domains with Sensitive Autofill Data"
            ])

            if analysis['high_risk_domains']:
                for domain in analysis['high_risk_domains'][:10]:  # Show top 10
                    report.append(f"- {domain}")
            else:
                report.append("No high-risk domains with sensitive autofill data detected")

        # Extension Risk Analysis
        if 'extension_risks' in risk_analyses:
            analysis = risk_analyses['extension_risks']
            report.extend([
                "",
                "## Browser Extension Risk Analysis",
                f"Risk Level: **{analysis['risk_level'].upper()}**",
                f"Total Extensions: {analysis['total_extensions']}",
                "",
                "### Security Extensions"
            ])

            if analysis['security_extensions']:
                for ext in analysis['security_extensions'][:5]:  # Show top 5
                    report.append(f"- {ext}")
            else:
                report.append("No security-focused extensions detected")

            report.append("")
            report.append("### Potentially Risky Extensions")

            if analysis['high_risk_extensions']:
                for ext in analysis['high_risk_extensions'][:5]:  # Show top 5
                    report.append(f"- {ext}")
            else:
                report.append("No high-risk extensions detected")

        # Temporal Pattern Analysis
        if 'temporal_patterns' in risk_analyses:
            analysis = risk_analyses['temporal_patterns']
            report.extend([
                "",
                "## Temporal Activity Pattern Analysis",
                f"Risk Level: **{analysis['risk_level'].upper()}**",
                "",
                "### Unusual Hours Activity"
            ])

            if analysis['unusual_hours_activity']:
                for activity in analysis['unusual_hours_activity']:
                    hour = activity['hour']
                    report.extend([
                        f"#### Activity at {hour}:00 - {hour+1}:00",
                        f"- Count: {activity['count']} login activities",
                        "- Example URLs:"
                    ])
                    for url in activity['urls'][:3]:  # Show top 3
                        report.append(f"  - {url}")
            else:
                report.append("No login activity during unusual hours detected")

            report.append("")
            report.append("### Activity Bursts")

            if analysis['activity_bursts']:
                for burst in analysis['activity_bursts']:
                    report.extend([
                        f"- Date: {burst['date']}",
                        f"  - Count: {burst['count']} (Expected: ~{burst['expected']})"
                    ])
            else:
                report.append("No unusual activity bursts detected")

        # Domain Network Analysis
        if 'domain_network' in risk_analyses:
            analysis = risk_analyses['domain_network']
            report.extend([
                "",
                "## Domain Network Analysis",
                f"Risk Level: **{analysis['risk_level'].upper()}**",
                "",
                "### High Centrality Domains"
            ])

            if analysis['high_centrality_domains']:
                for idx, domain_data in enumerate(analysis['high_centrality_domains'][:5]):  # Show top 5
                    report.append(f"{idx+1}. {domain_data['domain']} (Centrality: {domain_data['centrality']:.3f})")
            else:
                report.append("No high centrality domains identified")

            report.append("")
            report.append("### Unusual Domain Transitions")

            if analysis['unusual_transitions']:
                for idx, transition in enumerate(analysis['unusual_transitions'][:5]):  # Show top 5
                    report.append(f"{idx+1}. {transition['from']} → {transition['to']} (Weight: {transition['weight']})")
            else:
                report.append("No unusual domain transitions detected")

        # Recommendations
        report.extend([
            "",
            "## Security Recommendations",
            "",
            "Based on the analysis, consider the following actions:"
        ])

        # Add specific recommendations based on risk analyses
        recommendations = []

        if 'password_reuse' in risk_analyses and risk_analyses['password_reuse']['risk_level'] != 'low':
            recommendations.append("- Review rapid login sequences for potential password reuse across multiple sites")
            recommendations.append("- Consider implementing a password manager to avoid password reuse")

        if 'autofill_exposure' in risk_analyses and risk_analyses['autofill_exposure']['risk_level'] != 'low':
            recommendations.append("- Clear sensitive autofill data from browsers")
            recommendations.append("- Disable autofill for sensitive information on high-risk sites")

        if 'extension_risks' in risk_analyses and risk_analyses['extension_risks']['risk_level'] != 'low':
            recommendations.append("- Audit browser extensions and remove potentially risky ones")
            recommendations.append("- Install security-focused extensions from trusted sources")

        if 'temporal_patterns' in risk_analyses and risk_analyses['temporal_patterns']['risk_level'] != 'low':
            recommendations.append("- Investigate unusual login activity patterns, especially during non-business hours")
            recommendations.append("- Consider implementing time-based access controls")

        if 'domain_network' in risk_analyses and risk_analyses['domain_network']['risk_level'] != 'low':
            recommendations.append("- Examine unusual domain transitions for potential security issues")
            recommendations.append("- Consider network-level monitoring for suspicious traffic patterns")

        # Add general recommendations
        recommendations.extend([
            "- Ensure multi-factor authentication is enabled for all sensitive accounts",
            "- Regularly clear browser cookies and cached data",
            "- Keep browsers and extensions updated to the latest versions",
            "- Consider using a dedicated browser profile for sensitive activities"
        ])

        for recommendation in recommendations:
            report.append(recommendation)

        return "\n".join(report)

    def run_risk_analysis(self) -> Dict[str, Dict[str, Any]]:
        """
        Run a comprehensive risk analysis on browser forensic data.

        Returns:
            Dictionary containing all risk analysis results
        """
        # Load data from credential analysis
        logger.info("Loading credential analysis data...")
        data = self.load_analysis_data()

        if not data:
            logger.error("No analysis data found. Run credential_analyzer first.")
            return {}

        risk_analyses = {}

        # Run password reuse analysis
        logger.info("Analyzing password reuse patterns...")
        if 'login_data' in data:
            risk_analyses['password_reuse'] = self.analyze_password_reuse_risk(data['login_data'])

        # Run autofill exposure analysis
        logger.info("Analyzing autofill data exposure...")
        if 'autofill' in data:
            risk_analyses['autofill_exposure'] = self.analyze_autofill_exposure(data['autofill'])

        # Run extension risk analysis
        logger.info("Analyzing browser extension risks...")
        if 'extensions' in data:
            risk_analyses['extension_risks'] = self.analyze_extension_risks(data['extensions'])

        # Run temporal pattern analysis
        logger.info("Analyzing temporal login patterns...")
        if 'urls' in data:
            risk_analyses['temporal_patterns'] = self.analyze_login_temporal_patterns(data['urls'])

        # Run domain network analysis
        logger.info("Generating domain network analysis...")
        if 'urls' in data:
            risk_analyses['domain_network'] = self.generate_domain_network(data['urls'])

        # Calculate overall risk
        logger.info("Calculating overall risk score...")
        overall_risk = self.calculate_overall_risk_score(risk_analyses)

        # Generate comprehensive report
        logger.info("Generating risk report...")
        report = self.generate_risk_report(risk_analyses, overall_risk)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON results
        with open(self.output_dir / f"risk_analysis_{timestamp}.json", 'w') as f:
            json_data = {
                'analyses': risk_analyses,
                'overall_risk': overall_risk
            }
            json.dump(json_data, f, indent=2, default=str)

        # Save report
        with open(self.output_dir / f"security_risk_report_{timestamp}.md", 'w') as f:
            f.write(report)

        logger.info(f"Risk analysis complete! Results saved to {self.output_dir}")

        return {
            'analyses': risk_analyses,
            'overall_risk': overall_risk
        }


def main():
    """
    Main function to run from command line.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description='Browser Credential & Autofill Security Risk Analyzer',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--analysis-dir', '-a', required=True,
                      help='Directory containing credential analysis results')

    parser.add_argument('--output-dir', '-o',
                      help='Directory where risk analysis will be saved (defaults to analysis_dir/risk_analysis)')

    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose logging')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger().setLevel(log_level)

    logger.info("Browser Credential & Autofill Security Risk Analyzer")
    logger.info("=================================================")

    # Run risk analysis
    try:
        analyzer = CredentialRiskAnalyzer(args.analysis_dir, args.output_dir)
        analyzer.run_risk_analysis()
    except Exception as e:
        logger.error(f"Error during risk analysis: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())