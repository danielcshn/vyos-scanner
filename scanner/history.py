import traceback
import re

class History:
    def __init__(self):
        self.__name__ = 'History'

    def run_ssh(self, sshc):
        try:
            output = sshc.run_command("history")
            result = self.check_results_ssh(output)
            return result
        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, output):
            data = {
                'history_raw': output,
                'config_changes': [],
                'sensitive_commands': []
            }

            suspicious = []
            recommendation = []

            lines = output.strip().split('\n')

            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) < 3:
                    continue
                command = parts[2]

                if re.match(r'^(set|delete)\b', command):
                    data['config_changes'].append(command)
                elif re.match(r'^(sudo|cd|ls|tcpdump|iftop|rm|mv|cat|chmod|wget|chown)\b', command):
                    data['sensitive_commands'].append(command)

            if data['config_changes']:
                suspicious.append(f"[!] {len(data['config_changes'])} possible configuration changes were detected:")
                for cmd in data['config_changes']:
                    suspicious.append(f"    • {cmd}")
                recommendation.append("Review whether these changes were authorized and documented.")

            if data['sensitive_commands']:
                suspicious.append(f"[!] {len(data['sensitive_commands'])} sensitive commands were detected executed:")
                for cmd in data['sensitive_commands']:
                    suspicious.append(f"    • {cmd}")
                recommendation.append("Check whether the commands were executed by authorized personnel.")

            if not data['config_changes'] and not data['sensitive_commands']:
                recommendation.append("[✓] No recent sensitive changes or commands were detected.")

            return {
                'raw_data': data,
                'suspicious': '\n'.join(suspicious),
                'recommendation': recommendation
            }