#!/usr/bin/env python3
#
# BrOkEn_AuT (25-08-2025)
# Rewritten by Gemini
# Original by Venki (@Ganji)
# Please use responsibly... 
#

import requests
import pyfiglet
from termcolor import colored, cprint
import xml.etree.ElementTree as ET
import base64
import warnings
import sys
import json
import argparse
import os

# Check for dependencies and guide user
try:
    from prettytable import PrettyTable
except ImportError:
    cprint("Required libraries not found.", "red")
    # Check if venv exists
    import os
    if os.path.isdir('venv'):
        cprint("A virtual environment exists in the 'venv' directory.", "yellow")
        cprint("Please activate it by running: source venv/bin/activate", "yellow")
    else:
        cprint("Please install dependencies using: pip install -r requirements.txt", "yellow")
    sys.exit(1)


def print_banner():
    """Prints a simple ASCII banner."""
    banner = pyfiglet.figlet_format("BrOkEn_AuT")
    cprint(banner, 'cyan')
    cprint("by @ganji lvl.5 (rev. Gemini)".rjust(len(banner.split("\n")[0])), 'yellow')

def load_config(config_path):
    """Loads roles and settings from a JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        if 'roles' not in config or not config['roles']:
            raise ValueError("Config file must contain a non-empty 'roles' array.")
        if 'settings' not in config or 'expected_status_code' not in config['settings']:
            raise ValueError("Config file must contain 'settings' with 'expected_status_code'.")
            
        return config['roles'], config['settings']['expected_status_code']
    except FileNotFoundError:
        cprint(f"Error: Configuration file not found at '{config_path}'", "red")
        return None, None
    except json.JSONDecodeError:
        cprint(f"Error: Could not decode JSON from '{config_path}'", "red")
        return None, None
    except ValueError as e:
        cprint(f"Error in config file structure: {e}", "red")
        return None, None

def parse_burp_xml(file_path):
    """Loads and parses requests from a Burp Suite XML export."""
    requests_data = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            tree = ET.parse(file)
        root = tree.getroot()
        for item in root.findall('item'):
            try:
                url = item.find('url').text
                method = item.find('method').text
                request_b64 = item.find('request').text
                request_decoded = base64.b64decode(request_b64).decode('utf-8', errors='ignore')

                header_part, _, body = request_decoded.partition('\r\n\r\n')
                header_lines = header_part.split('\r\n')[1:]
                
                original_headers = {
                    key.strip(): value.strip()
                    for line in header_lines
                    if ': ' in line
                    for key, value in [line.split(': ', 1)]
                    if key.lower() not in ['host', 'content-length']
                }

                requests_data.append({
                    'url': url,
                    'method': method,
                    'body': body or None,
                    'original_headers': original_headers
                })
            except (AttributeError, IndexError) as e:
                cprint(f"Skipping an item in XML due to parsing error: {e}", "yellow")
                continue
        if not requests_data:
            raise ValueError(f"No valid requests found in '{file_path}'.")
        return requests_data
    except FileNotFoundError:
        cprint(f"Error: Burp file not found at '{file_path}'", "red")
    except ET.ParseError:
        cprint(f"Error: Invalid XML in '{file_path}'.", "red")
    except Exception as e:
        cprint(f"An unexpected error occurred: {e}", "red")
    return []

def generate_curl_command(method, url, headers, body):
    """Generates a curl command for a given request."""
    command = [f"curl -k -X {method}"]
    for key, value in headers.items():
        command.append(f"-H '{key}: {value}'")
    if body:
        body_escaped = body.replace("'", "'\\''")
        command.append(f"--data-raw '{body_escaped}'")
    command.append(f'"{url}"')
    return " ".join(command)

def generate_report(output_file, summary, vuln_table, full_table):
    """Writes the final report to a file."""
    with open(output_file, "w", encoding="utf-8") as out:
        out.write("="*60 + "\n")
        out.write(" BrOkEn_AuT - Executive Summary\n")
        out.write("="*60 + "\n\n")
        out.write(summary + "\n\n")

        if vuln_table:
            out.write("="*80 + "\n")
            out.write(" 🔥 Vulnerability Details\n")
            out.write("="*80 + "\n\n")
            out.write(vuln_table.get_string() + "\n\n")

        out.write("="*80 + "\n")
        out.write(" 📋 Full Test Log\n")
        out.write("="*80 + "\n\n")
        out.write(full_table.get_string())
    cprint(f"\n✅ Report saved to '{output_file}'", "green")

def test_endpoints(requests_data, user_roles, expected_status, output_file, proxy_url=None):
    """The main testing function."""
    all_results = []
    vulnerabilities = []
    highest_priv_role = user_roles[0]
    lower_priv_roles = user_roles[1:]
    proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None

    for i, req_data in enumerate(requests_data, 1):
        url, method, body, original_headers = req_data.values()
        print(f"\nTesting Endpoint #{i}: {method} {url}")
        try:
            baseline_headers = highest_priv_role['headers']
            baseline_resp = requests.request(method, url, headers=baseline_headers, data=body, timeout=10, verify=False, proxies=proxies)
            all_results.append([i, highest_priv_role['name'], method, url, baseline_resp.status_code, "Baseline"])
        except requests.exceptions.RequestException as e:
            cprint(f"Error on baseline request: {e}", "red")
            all_results.append([i, highest_priv_role['name'], method, url, "ERROR", str(e)])
            continue

        for role in lower_priv_roles:
            try:
                role_headers = role['headers']
                response = requests.request(method, url, headers=role_headers, data=body, timeout=10, verify=False, proxies=proxies)
                status = response.status_code
                if status != expected_status:
                    finding = "Potential BAC Bypass!"
                    cprint(f"  🔥 VULNERABILITY: Role '{role['name']}' got status {status} (expected {expected_status})", 'magenta')
                    curl_cmd = generate_curl_command(method, url, role_headers, body)
                    vulnerabilities.append({
                        'bypassed': highest_priv_role['name'], 'requester': role['name'],
                        'method': method, 'url': url, 'status': status, 'curl': curl_cmd
                    })
                else:
                    finding = "OK (Expected)"
                all_results.append([i, role['name'], method, url, status, finding])
            except requests.exceptions.RequestException as e:
                cprint(f"  Error for role '{role['name']}': {e}", "red")
                all_results.append([i, role['name'], method, url, "ERROR", str(e)])

    num__vulns = len(vulnerabilities)
    summary_text = f"Scan Complete.\n\n  Endpoints Tested: {len(requests_data)}\n  Roles Assessed:   {len(user_roles)}\n  Potential Issues: {num__vulns}"

    vuln_table_report = None
    if vulnerabilities:
        # For the report
        vuln_table_report = PrettyTable()
        vuln_table_report.field_names = ["Bypassed Role", "Requester Role", "Method", "URL", "Status", "Reproduction (cURL)"]
        vuln_table_report.align = 'l'
        vuln_table_report.max_width["Reproduction (cURL)"] = 60
        
        # For the console
        console_table = PrettyTable()
        console_table.field_names = ["Bypassed Role", "Requester Role", "Method", "URL", "Status"]
        console_table.align = 'l'
        console_table.max_width["URL"] = 110

        for v in vulnerabilities:
            vuln_table_report.add_row([
                colored(v['bypassed'], 'yellow'), colored(v['requester'], 'red'), v['method'],
                v['url'], colored(v['status'], 'red'), v['curl']
            ])
            console_table.add_row([
                colored(v['bypassed'], 'yellow'), colored(v['requester'], 'red'), v['method'],
                v['url'], colored(v['status'], 'red')
            ])
        print(console_table)

    full_table = PrettyTable()
    full_table.field_names = ["ID", "Role", "Method", "URL", "Status", "Finding"]
    full_table.align = 'l'
    for row in all_results:
        full_table.add_row(row)
    
    generate_report(output_file, summary_text, vuln_table_report, full_table)


if __name__ == "__main__":
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    parser = argparse.ArgumentParser(
        description="BrOkEn_AuT: A tool for finding Broken Access Control vulnerabilities.",
        epilog="Example: python3 broken_aut.py -c config.json -b burp.xml -o report.txt -p http://127.0.0.1:8080"
    )
    parser.add_argument("-c", "--config", required=True, help="Path to the JSON config file.")
    parser.add_argument("-b", "--burp-file", required=True, help="Path to the Burp XML export.")
    parser.add_argument("-o", "--output-file", required=True, help="Path for the output report.")
    parser.add_argument("-p", "--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()
    print_banner()
    user_roles, expected_status = load_config(args.config)
    if user_roles is None: sys.exit(1)
    requests_data = parse_burp_xml(args.burp_file)
    if not requests_data: sys.exit(1)
    test_endpoints(requests_data, user_roles, expected_status, args.output_file, args.proxy)