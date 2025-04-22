import traceback
import re

class Console:
    def __init__(self):
        self.__name__ = 'Console'

    def run_ssh(self, sshc):
        suspicious = []
        recommendation = []

        try:
            # Get traditional console settings
            raw_output_console = sshc.run_command("show configuration commands | match console")
            lines = raw_output_console.strip().splitlines()
            config_console = [line for line in lines if line.strip().startswith("set system console device")]
            data_console = "\n".join(config_console)

            # Get console-server configuration (Dropbear case)
            raw_output_server = sshc.run_command("show configuration commands | match service console-server")
            lines_server = raw_output_server.strip().splitlines()
            config_server = [line for line in lines_server if line.strip().startswith("set service console-server")]
            data_server = "\n".join(config_server)

            for line in config_console:
                match_device = re.search(r"set system console device (\S+)", line)
                if match_device:
                    device = match_device.group(1)
                    suspicious.append(f"Console device configured: {device}")

                match_speed = re.search(r"set system console device \S+ speed '(\d+)'", line)
                if match_speed:
                    speed = match_speed.group(1)
                    suspicious.append(f"Console speed configured: {speed} bps")

            if config_console:
                recommendation.append(
                    "Console access is configured. If not explicitly needed (e.g., for recovery), consider removing it and using SSH instead."
                )
                recommendation.append(
                    "Serial consoles are slow and limited. Disable unless required for diagnostics."
                )

            # Analyze vulnerable console-server configuration
            if config_server:
                for line in config_server:
                    if re.search(r"ssh \{", line) or "ssh port" in line:
                        suspicious.append("Console-server SSH configuration detected. This may be vulnerable to CVE-2025-30095 (Dropbear key reuse).")

                recommendation.append(
                    "Avoid using 'console-server' over SSH unless necessary. Previous VyOS versions reused Dropbear host keys, making SSH vulnerable to MitM attacks (CVE-2025-30095)."
                )
                recommendation.append(
                    "Ensure you are using VyOS 1.4.2 or later, which regenerates Dropbear keys to prevent key reuse. Avoid sharing disk images across systems without key regeneration."
                )

            data = "\n".join(filter(None, [data_console, data_server]))

        except Exception as e:
            traceback.print_exc()
            suspicious.append(f"Error analyzing console config: {str(e)}")
            data = ""

        return {
            'raw_data': data,
            'suspicious': suspicious,
            'recommendation': recommendation
        }