import os
import requests
import argparse
import json
from datetime import datetime, timedelta

from scanner.sshclient import SSHClient
from scanner.history import History
from scanner.sshguard import SSHGuard
from scanner.console import Console
from scanner.ports import Ports
from scanner.system import System
from scanner.users import Users
from scanner.packages import Packages
from scanner.nistcve import NistCVE
from scanner.version import Version
from scanner.built import Built

LOCAL_JSON = './data/vyos_cves.json'
KEYWORDS = ["vyos"]
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_AGE_DAYS = 15

def main(args):
    all_data = {}

    if args.skip_cve:
    	commands = [Version(), Users(), Built(), System(), Ports(), SSHGuard(), Console(), History()]
    else:
    	commands = [Version(), Users(), Built(), System(), Ports(), SSHGuard(), Console(), History(), NistCVE(), Packages()]

    if args.update or needs_update(LOCAL_JSON, MAX_AGE_DAYS):
        #print("[*] Updating local CVE database...")
        update_cve_data(LOCAL_JSON, KEYWORDS)
    #else:
        #print(f"[✓] Local CVE file is up to date ({LOCAL_JSON})")

    if not args.json:
        print(f'\n[+] VyOS IP Address: {args.ip}\n')

    ssh_client = SSHClient(args.ip, args.username, args.password, int(args.port), args.key)
    ssh_client.connect()
    
    for command in commands:
        res = command.run_ssh(ssh_client)
        all_data[command.__name__] = res

    if args.json:
        print(json.dumps(all_data, indent=4))
    else:
        print_txt_results(all_data, args.concise)
    
    ssh_client.disconnect()

def print_txt_results(res, concise):
    for command in res:
        if (not concise and res[command]["raw_data"]) or res[command].get("recommendation") or res[command].get("suspicious"):
            print(f'{command}:')
            for item in res[command]:
                if concise and item != "recommendation" and item != "suspicious":
                    continue
                if res[command][item]:
                    print(f'\t{item}:')
                    if isinstance(res[command][item], list):
                        data = '\n\t\t'.join(res[command][item])  # ya son strings formateados
                    else:
                        data = res[command][item]
                    print(f'\t\t{data}')

def needs_update(filepath, max_days=15):
    if not os.path.exists(filepath):
        return True
    created = datetime.fromtimestamp(os.path.getmtime(filepath))
    now = datetime.now()
    return (now - created) > timedelta(days=max_days)

def update_cve_data(filepath, keywords):
    all_vulns = []

    print("[*] Querying the NVD API...")
    for keyword in keywords:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 2000
        }

        try:
            response = requests.get(API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            print(f"[+] '{keyword}' → {len(vulns)} vulnerabilities found!")
        except Exception as e:
            print(f"[!] Error while querying '{keyword}': {e}")

    if all_vulns:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(all_vulns, f, indent=2)
        print(f"[✓] File updated with {len(all_vulns)} vulnerabilities → {filepath}")
    else:
        print("[!] No results found, file not updated.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='The tested VyOS IP address', required=True)
    parser.add_argument('-p', '--port', help='The tested VyOS SSH port', default='22')
    parser.add_argument('-u', '--username', help='User name with admin Permissions', required=True)
    parser.add_argument('-ps', '--password', help='The password of the given user name', default='vyos')
    parser.add_argument('-k', '--key', help='Filename of optional private key(s) and/or certs to try for authentication', default='')
    parser.add_argument('-j', '--json', help='Print the results as json format', action='store_true')
    parser.add_argument('-c', '--concise', help='Print out only suspicious items and recommendations', action='store_true')
    parser.add_argument('-ud', '--update', help='Update the CVE Json file', action='store_true')
    parser.add_argument('-sc', '--skip-cve', help='Skip CVE checks', action='store_true')
    args = parser.parse_args()

    main(args)
