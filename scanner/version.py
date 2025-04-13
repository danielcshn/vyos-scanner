import traceback
import re

class Version:
    def __init__(self):
        self.__name__ = 'Version'

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
                    release_name = result['release_name']
                    support_status = result['support_status']
                    raw_data = result['raw_data']
                    recommendation = result['recommendation']
                    #print(f"[!] VyOS Build Information: {raw_data} - ({release_name}) - {support_status} {recommendation}")
                #else:
                    #print("[!] Version information could not be determined.")

                return {'raw_data': version,
                'release_name': release_name,
                'support_status': support_status,
                'recommendation': recommendation}
            else:
                raise Exception("No valid version was found in the command output.")

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, version):

        status = {
            '1.0': ('Hydrogen', 'Unsupported', 'End of Life'),
            '1.1': ('Helium', 'Unsupported', 'End of Life'),
            '1.2': ('Crux', 'Unsupported', 'End of Life'),
            '1.3': ('Equuleus', 'Unsupported', 'End of Life in April 2025'),
            '1.4': ('Sagitta', 'Supported', 'Maintenance and security release - supported until 2028'),
            '1.5': ('Circinus', 'Supported', 'Development branch - supported until 2028')
        }

        try:
            # Extract base version (e.g. 1.2 from 1.2.9 or 1.5-rolling-20240616)
            version_match = re.match(r'(\d+\.\d+)', version)
            if version_match:
                base_version = version_match.group(1)

                if base_version in status:
                    release_name, support_status, comment = status[base_version]

                    # Build list of supported versions from the dictionary
                    supported_versions = [
                        f"{ver} ({status[ver][0]})"
                        for ver in sorted(status)
                        if status[ver][1] == 'Supported'
                    ]

                    if support_status == 'Unsupported':
                        recommendation = (
                            f"Version {version} ({release_name}) is no longer officially supported."
                            f"It is recommended to upgrade to a supported version: {', '.join(supported_versions)}."
                        )
                    else:
                        recommendation = (
                            f"Version {version} ({release_name}) is supported. {comment}"
                        )

                    return {
                        'release_name': release_name,
                        'support_status': support_status,
                        'raw_data': version,
                        'recommendation': recommendation
                    }

            return {
                'release_name': 'Unknown',
                'support_status': 'Unknown',
                'raw_data': version,
                'recommendation': 'Support status of this release could not be determined.'
            }

        except Exception:
            print(traceback.format_exc())
            return None