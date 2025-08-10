#!/usr/bin/env python3
import os
import json
import re
import csv
import argparse
from datetime import datetime
from collections import defaultdict

class BrowserExtensionAnalyzer:
    """Analyzes browser extensions from forensic data"""

    def __init__(self, extensions_json_path, output_dir):
        self.extensions_json_path = extensions_json_path
        self.output_dir = output_dir
        self.extensions = {}
        self.extension_files = defaultdict(list)
        self.known_high_risk_permissions = [
            "tabs",
            "webNavigation",
            "webRequest",
            "webRequestBlocking",
            "cookies",
            "storage",
            "history",
            "downloads",
            "clipboardRead",
            "clipboardWrite",
            "geolocation",
            "proxy",
            "enterprise.platformKeys",
            "pageCapture",
            "nativeMessaging"
        ]

        # Known extension IDs with names
        # This helps identify extensions when we only have the ID
        self.known_extensions = {
            "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
            "nmmhkkegccagdldgiimedpiccmgmieda": "Chrome Web Store Payments",
            "kjeghcllfecehndceplomkocgfbklffd": "TeamViewer",
            "pkedcjkdefgpdelpbcmbmeomcjbeemfm": "Chrome Media Router",
            "aapocclcgogkmnckokdopfmhonfmgoek": "Google Slides",
            "aohghmighlieiainnegkcijnfilokake": "Google Docs",
            "apdfllckaahabafndbhieahigkjlhalf": "Google Drive",
            "blpcfgokakmgnkcojhhkbfbldkacnbeo": "YouTube",
            "felcaaldnbdncclmgdcncolpebgiejap": "Google Sheets",
            "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
            "nmmhkkegccagdldgiimedpiccmgmieda": "Chrome Web Store Payments",
            "pjkljhegncpnkpknbcohdijeoejaedia": "Gmail",
            "pkedcjkdefgpdelpbcmbmeomcjbeemfm": "Google Cast",

            # Identified from the search
            "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask - Ethereum Wallet",
            "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare Wallet - Solana Wallet",
            "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Last Pass Password Manager",
            "bmnlcjabgnpnenekpadlanbbkooimhnj": "Coinbase Wallet",
            "efbglgofoippbgcjepnhiblaibcnclgk": "Sender Wallet - Solana Wallet",
            "efaidnbmnnnibpcajpcglclefindmkaj": "Adobe Acrobat Reader",
            "mgijmajocgfcbeboacabfgobmjgjcoja": "Crypto Pro - Token Portfolio",
            "fheoggkfdfchfphceeifdbepaooicaho": "McAfee WebAdvisor",
            "dmkamcknogkgcdfhhbddcghachkejeap": "Bitwarden - Password Manager",
            "aegnopegbbhjeeiganiajffnalhlkkjb": "CamelCamelCamel - Amazon Price Tracker",
            "pgphcomnlaojlmmcjmiddhdapjpbgeoc": "Adblock Plus - ad blocker",
            "opcgpfmipidbgpenhmajoajpbobppdil": "Keeper Password Manager",
            "fjoaledfpmneenckfbpdfhkmimnjocfa": "Exodus Wallet"
        }

        # Categorize extensions by type for risk assessment
        self.extension_categories = {
            "crypto_wallet": [
                "nkbihfbeogaeaoehlefnkodbefgpgknn",  # MetaMask
                "bhhhlbepdkbapadjdnnojkbgioiodbic",  # Solflare
                "bmnlcjabgnpnenekpadlanbbkooimhnj",  # Coinbase Wallet
                "efbglgofoippbgcjepnhiblaibcnclgk",  # Sender Wallet
                "mgijmajocgfcbeboacabfgobmjgjcoja",  # Crypto Pro
                "fjoaledfpmneenckfbpdfhkmimnjocfa"   # Exodus Wallet
            ],
            "password_manager": [
                "bfnaelmomeimhlpmgjnjophhpkkoljpa",  # LastPass
                "dmkamcknogkgcdfhhbddcghachkejeap",  # Bitwarden
                "opcgpfmipidbgpenhmajoajpbobppdil"   # Keeper
            ],
            "remote_access": [
                "kjeghcllfecehndceplomkocgfbklffd"   # TeamViewer
            ],
            "security": [
                "fheoggkfdfchfphceeifdbepaooicaho"   # McAfee WebAdvisor
            ],
            "productivity": [
                "efaidnbmnnnibpcajpcglclefindmkaj",  # Adobe Acrobat
                "aegnopegbbhjeeiganiajffnalhlkkjb",  # CamelCamelCamel
                "pgphcomnlaojlmmcjmiddhdapjpbgeoc"   # Adblock Plus
            ]
        }

    def load_data(self):
        """Load extension data from JSON file"""
        print(f"Loading extension data from {self.extensions_json_path}")
        try:
            with open(self.extensions_json_path, 'r', encoding='utf-8') as f:
                self.extension_data = json.load(f)
            print(f"Loaded {len(self.extension_data)} records")
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False

    def extract_extensions(self):
        """Extract Chrome extension information from file entries"""
        extension_pattern = re.compile(r"\\Users\\[^\\]+\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\([a-z]{32})\\([^\\]+)")
        manifest_pattern = re.compile(r"\\Users\\[^\\]+\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\([a-z]{32})\\[^\\]+\\manifest.json")

        print("Extracting extension information...")
        extension_count = 0

        # Process each file entry
        for entry in self.extension_data:
            if "message" not in entry:
                continue

            # Skip entries that aren't files
            message = entry.get("message", "")
            if "Type: file" not in message and "Type: directory" not in message:
                continue

            # Process Chrome extension paths
            manifest_match = manifest_pattern.search(message)
            if manifest_match:
                extension_id = manifest_match.group(1)
                if extension_id not in self.extensions:
                    self.extensions[extension_id] = {
                        "id": extension_id,
                        "name": self.known_extensions.get(extension_id, "Unknown Extension"),
                        "versions": set(),
                        "files": [],
                        "manifest_found": True,
                        "timestamp": entry.get("timestamp"),
                        "risk_level": "Unknown",
                        "category": self.get_extension_category(extension_id)
                    }
                    extension_count += 1

            # Extract all extension files for further analysis
            ext_match = extension_pattern.search(message)
            if ext_match:
                extension_id = ext_match.group(1)
                version = ext_match.group(2)

                if extension_id not in self.extensions:
                    self.extensions[extension_id] = {
                        "id": extension_id,
                        "name": self.known_extensions.get(extension_id, "Unknown Extension"),
                        "versions": set(),
                        "files": [],
                        "manifest_found": False,
                        "timestamp": entry.get("timestamp"),
                        "risk_level": "Unknown",
                        "category": self.get_extension_category(extension_id)
                    }
                    extension_count += 1

                self.extensions[extension_id]["versions"].add(version)
                self.extensions[extension_id]["files"].append({
                    "path": message.split("Type:")[0].strip(),
                    "type": "file" if "Type: file" in message else "directory",
                    "timestamp": entry.get("timestamp")
                })

        # Process extension data
        for ext_id, ext_data in self.extensions.items():
            ext_data["versions"] = list(ext_data["versions"])

            # Assign risk levels based on categories
            self.assign_risk_level(ext_id, ext_data)

        print(f"Extracted {extension_count} extensions")
        return self.extensions

    def get_extension_category(self, extension_id):
        """Get the category of an extension based on its ID"""
        for category, ext_ids in self.extension_categories.items():
            if extension_id in ext_ids:
                return category
        return "unknown"

    def assign_risk_level(self, ext_id, ext_data):
        """Assign risk level based on extension category and knowledge"""
        category = ext_data["category"]

        if category == "remote_access":
            ext_data["risk_level"] = "High"
        elif category == "crypto_wallet":
            ext_data["risk_level"] = "High"  # Crypto wallets are high risk for data exfiltration
        elif category == "password_manager":
            ext_data["risk_level"] = "Medium"  # Password managers have access to sensitive data
        elif ext_id in self.known_extensions and "Google" in self.known_extensions[ext_id]:
            ext_data["risk_level"] = "Low"  # Google extensions generally low risk
        elif category == "productivity":
            ext_data["risk_level"] = "Low"
        elif category == "security":
            ext_data["risk_level"] = "Low"
        else:
            ext_data["risk_level"] = "Medium"  # Unknown extensions are medium risk

    def generate_reports(self):
        """Generate reports for the extracted extensions"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

        # Generate CSV report
        csv_path = os.path.join(self.output_dir, f"browser_extensions_{timestamp}.csv")
        with open(csv_path, 'w', newline='') as csvfile:
            fieldnames = ['id', 'name', 'category', 'versions', 'manifest_found', 'file_count', 'risk_level', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for ext_id, ext_data in self.extensions.items():
                writer.writerow({
                    'id': ext_id,
                    'name': ext_data['name'],
                    'category': ext_data['category'],
                    'versions': ', '.join(ext_data['versions']),
                    'manifest_found': ext_data['manifest_found'],
                    'file_count': len(ext_data['files']),
                    'risk_level': ext_data['risk_level'],
                    'timestamp': ext_data['timestamp']
                })

        print(f"Saved CSV report to {csv_path}")

        # Generate Markdown report
        md_path = os.path.join(self.output_dir, f"browser_extensions_{timestamp}.md")
        with open(md_path, 'w') as f:
            f.write("# Browser Extension Analysis Report\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

            # Overall statistics
            f.write("## Overall Statistics\n\n")
            f.write(f"- Total extensions found: {len(self.extensions)}\n")

            # Count by category
            categories = defaultdict(int)
            for ext in self.extensions.values():
                categories[ext["category"]] += 1

            f.write("### Extensions by Category\n\n")
            for category, count in sorted(categories.items()):
                f.write(f"- {category.replace('_', ' ').title()}: {count}\n")
            f.write("\n")

            # Risk assessment
            risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
            for ext in self.extensions.values():
                risk_counts[ext["risk_level"]] += 1

            f.write("### Extensions by Risk Level\n\n")
            f.write(f"- High risk extensions: {risk_counts['High']}\n")
            f.write(f"- Medium risk extensions: {risk_counts['Medium']}\n")
            f.write(f"- Low risk extensions: {risk_counts['Low']}\n\n")

            # High risk extensions
            high_risk = [ext for ext in self.extensions.values() if ext["risk_level"] == "High"]
            if high_risk:
                f.write("## High Risk Extensions\n\n")
                for ext in high_risk:
                    f.write(f"### {ext['name']} ({ext['id']})\n\n")
                    f.write(f"- Category: {ext['category'].replace('_', ' ').title()}\n")
                    f.write(f"- Versions: {', '.join(ext['versions'])}\n")
                    f.write(f"- Timestamp: {ext['timestamp']}\n")
                    f.write(f"- File count: {len(ext['files'])}\n\n")

                    if ext['category'] == 'remote_access':
                        f.write("**Risk assessment:** This extension allows remote access to the computer and could be used for unauthorized access or data exfiltration.\n\n")
                    elif ext['category'] == 'crypto_wallet':
                        f.write("**Risk assessment:** This cryptocurrency wallet extension has access to sensitive cryptographic keys and financial data. It could be used to transfer cryptocurrency assets.\n\n")

            # Extensions by category
            f.write("## Extensions by Category\n\n")

            # Group extensions by category
            category_extensions = defaultdict(list)
            for ext_id, ext in self.extensions.items():
                category_extensions[ext["category"]].append(ext)

            # Write each category
            for category, exts in sorted(category_extensions.items()):
                f.write(f"### {category.replace('_', ' ').title()} Extensions\n\n")
                for ext in sorted(exts, key=lambda x: x["name"]):
                    f.write(f"#### {ext['name']} ({ext['id']})\n\n")
                    f.write(f"- Risk level: {ext['risk_level']}\n")
                    f.write(f"- Versions: {', '.join(ext['versions'])}\n")
                    f.write(f"- Manifest found: {ext['manifest_found']}\n")
                    f.write(f"- Timestamp: {ext['timestamp']}\n")
                    f.write(f"- File count: {len(ext['files'])}\n\n")

            # All extensions
            f.write("## All Installed Extensions\n\n")
            for ext_id, ext in sorted(self.extensions.items(), key=lambda x: x[1]["name"]):
                f.write(f"### {ext['name']} ({ext['id']})\n\n")
                f.write(f"- Category: {ext['category'].replace('_', ' ').title()}\n")
                f.write(f"- Risk level: {ext['risk_level']}\n")
                f.write(f"- Versions: {', '.join(ext['versions'])}\n")
                f.write(f"- Manifest found: {ext['manifest_found']}\n")
                f.write(f"- Timestamp: {ext['timestamp']}\n")
                f.write(f"- File count: {len(ext['files'])}\n\n")

        print(f"Generated markdown report at {md_path}")
        return md_path


def main():
    parser = argparse.ArgumentParser(description='Analyze browser extensions from forensic data')
    parser.add_argument('--extensions-json', required=True, help='Path to the extensions JSON file')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize and run analyzer
    analyzer = BrowserExtensionAnalyzer(args.extensions_json, args.output_dir)
    if analyzer.load_data():
        analyzer.extract_extensions()
        analyzer.generate_reports()
        print("Analysis complete!")
    else:
        print("Failed to load data. Aborting analysis.")


if __name__ == "__main__":
    main()