import traceback
import re

class SSHGuard:
    def __init__(self):
        self.__name__ = 'SSHGuard'

    def run_ssh(self, sshc):

        # https://www.sshguard.net/
        # https://blog.vyos.io/vyos-project-august-2023-update
        # https://github.com/vyos/vyos-documentation/pull/1127

        try:
            version_output = sshc.run_command("show version")
            version_match = re.search(r'Version:\s*VyOS\s+([\w\.\-]+)', version_output)
            version = version_match.group(1).strip() if version_match else None

            data = {
                'version': version,
                'raw_version_output': version_output,
                'config_check': '',
                'blocklist': ''
            }

            suspicious = []
            recommendation = []

            if version is None:
                suspicious.append("[!] Could not determine VyOS version")
                return {
                    'raw_data': data,
                    'suspicious': '\n'.join(suspicious),
                    'recommendation': recommendation
                }

            version_num_match = re.match(r'(\d+)\.(\d+)\.(\d+)', version)
            if not version_num_match:
                suspicious.append(f"[!] Unknown version format: {version}")
                return {
                    'raw_data': data,
                    'suspicious': '\n'.join(suspicious),
                    'recommendation': recommendation
                }

            version_parts = list(map(int, version_num_match.groups()))
            if version_parts < [1, 3, 4]:
                suspicious.append(f"[!] SSHGuard not supported in this version ({version})")
                recommendation.append("Upgrade to VyOS 1.4 or higher for SSH Guard support")
                return {
                    'raw_data': data,
                    'suspicious': '\n'.join(suspicious),
                    'recommendation': recommendation
                }

            # Check if ssh dynamic-protection is active
            config_output = sshc.run_command("show configuration commands | match ssh | match dynamic-protection")
            data['config_check'] = config_output

            allow_from = re.findall(r"allow-from\s+'([^']+)'", config_output)
            block_time_match = re.search(r"block-time\s+'(\d+)'", config_output)
            threshold_match = re.search(r"threshold\s+'(\d+)'", config_output)

            if not allow_from and not block_time_match and not threshold_match:
                suspicious.append("[!] SSH dynamic-protection is not configured")
                recommendation.append("It is recommended to enable SSH dynamic-protection to protect against brute force attacks.")
            else:
                recommendation.append("[!] SSH dynamic-protection enabled with the following values:")
                if threshold_match:
                    recommendation.append(f" - Threshold: {threshold_match.group(1)}")
                else:
                    suspicious.append("[!] Missing parameter: threshold")

                if block_time_match:
                    recommendation.append(f" - Block-time: {block_time_match.group(1)} segundos")
                else:
                    suspicious.append("[!] Missing parameter: block-time")

                if allow_from:
                    recommendation.append(" - Allow-from:")
                    for ip_range in allow_from:
                        recommendation.append(f"    • {ip_range}")
                else:
                    suspicious.append("[!] Missing parameter: allow-from")

            # If it is VyOS 1.4 or higher, try to get locks
            if version_parts >= [1, 4, 0]:
                blocklist_output = sshc.run_command("show ssh dynamic-protection")
                data['blocklist'] = blocklist_output

                blocked_ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', blocklist_output)
                if blocked_ips:
                    suspicious.append("[!] IPs blocked by SSHGuard were detected:")
                    for ip in blocked_ips:
                        suspicious.append(f"    • {ip}")
                    recommendation.append("Review suspicious connection attempts listed above")
                else:
                    recommendation.append("[!] There are no IPs currently blocked by SSHGuard")

            return {
                'raw_data': data,
                'suspicious': '\n'.join(suspicious),
                'recommendation': recommendation
            }

        except Exception:
            print(traceback.format_exc())
            return None
