import traceback
import re

class Console:
    def __init__(self):
        self.__name__ = 'Console'

    def run_ssh(self, sshc):
        suspicious = []
        recommendation = []

        try:
            raw_output = sshc.run_command("show configuration commands | match console")
            lines = raw_output.strip().splitlines()

            config_lines = [line for line in lines if line.strip().startswith("set system console device")]
            data = "\n".join(config_lines)

            for line in config_lines:
                match_device = re.search(r"set system console device (\S+)", line)
                if match_device:
                    device = match_device.group(1)
                    suspicious.append(f"Console device configured: {device}")

                match_speed = re.search(r"set system console device \S+ speed '(\d+)'", line)
                if match_speed:
                    speed = match_speed.group(1)
                    suspicious.append(f"Console device {device} speed configured: {speed} bps")

            if config_lines:
                recommendation.append(
                    "Console access is configured. If not explicitly needed (e.g., for disaster recovery), "
                    "it's recommended to remove it and use SSH instead."
                )
                recommendation.append(
                    "Serial consoles are slower and limited. Disable them unless required for remote recovery or low-level diagnostics."
                )

        except Exception as e:
            traceback.print_exc()
            suspicious.append(f"Error parsing console config: {str(e)}")
            data = ""

        return {
            'raw_data': data,
            'suspicious': suspicious,
            'recommendation': recommendation
        }