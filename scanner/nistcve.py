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

            #match = re.search(r'Version:\s*VyOS\s+([0-9]+\.[0-9]+\.[0-9]+)', data)
            match = re.search(r'Version:\s*VyOS\s+([\w\.\-]+)', data)
            if match:
                version = match.group(1)
                #print(f"[+] VyOS version detected: {version}")

                result = self.check_results_ssh(version)
                if result:
                    print(f"\n[!] {len(result)} CVEs affecting version {version} were detected:\n")
                    for cve in result:
                        #print(f"- {cve['id']}: {cve['description'][:150]}...")
                        print(f"- {cve['id']}: {cve['description']}")
                    return {
                        'raw_data': version,
                        'vulnerable_cves': result
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

                # 1. Buscar en las descripciones si mencionan la versión directamente
                descriptions = cve.get("descriptions", [])
                found_in_description = any(version in desc.get("value", "") for desc in descriptions)

                # 2. Buscar en criteria del cpeMatch
                found_in_criteria = False
                configurations = cve.get("configurations", [])
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            criteria = cpe.get("criteria", "")
                            # Busca la versión exacta en la CPE (ej: vyos:1.1.8)
                            if re.search(rf":{re.escape(version)}(?=[:*])", criteria):
                                found_in_criteria = True
                                break
                        if found_in_criteria:
                            break

                # Si aparece en alguna parte, lo agregamos
                if found_in_description or found_in_criteria:
                    description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "es"), None)
                    if not description:
                        description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "No description.")
                    cve_matches.append({
                        "id": cve_id,
                        "description": description
                    })

            return cve_matches

        except Exception:
            print(traceback.format_exc())
            return None