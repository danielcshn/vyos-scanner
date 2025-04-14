import traceback
import json
import os
import re

class NistCVE:
    def __init__(self):
        self.__name__ = 'NistCVE'
        self.local_cve_file = './data/vyos_cves.json'

    def run_ssh(self, sshc):
        version = ''

        try:
            data = sshc.run_command("show version")
            #print(data)  # Debug

            match = re.search(r'Version:\s*VyOS\s+([\w\.\-]+)', data)
            if match:
                version = match.group(1)
                #print(f"[+] VyOS version detected: {version}")

                result = self.check_results_ssh(version)
                if result:
                    result_cves = []
                    #print(f"\n[!] {len(result)} CVEs affecting version {version} were detected:\n")
                    for cve in result:

                        result_cves.append(
                            f"{cve['id']}: {cve['description']} - Recommendation: {cve['recommendation']}"
                        )

                    return {
                        'raw_data': version,
                        'suspicious': f'{len(result_cves)} CVEs found',
                        'recommendation': result_cves
                    }
                else:
                    return {
                        'raw_data': version,
                        'suspicious': 'NO CVEs FOUND',
                        'recommendation': 'No known CVEs found for this version'
                    }
            else:
                raise Exception("No valid version was found in the command output.")

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, version):
        cve_matches = []

        if not os.path.isfile(self.local_cve_file):
            print("[!] Vulnerability file not found.")
            return None

        try:
            with open(self.local_cve_file, 'r', encoding='utf-8') as f:
                vulnerabilities = json.load(f)

            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")

                descriptions = cve.get("descriptions", [])
                found_in_description = any(version in desc.get("value", "") for desc in descriptions)

                found_in_criteria = False
                configurations = cve.get("configurations", [])
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            criteria = cpe.get("criteria", "")
                            # Look for the exact version in the CPE (e.g. vyos:1.1.8)
                            if re.search(rf":{re.escape(version)}(?=[:*])", criteria):
                                found_in_criteria = True
                                break
                        if found_in_criteria:
                            break

                if found_in_description or found_in_criteria:
                    description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), None)
                    recommendation = f'VyOS version: {version} is vulnerable to CVE(s). Upgrade to the latest version. (The CVEs list is from NVD)'
                    if not description:
                        description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "No description.")
                    cve_matches.append({
                        "id": cve_id,
                        "description": description,
                        "recommendation": recommendation
                    })

            return cve_matches

        except Exception:
            print(traceback.format_exc())
            return None