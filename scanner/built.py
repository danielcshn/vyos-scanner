import traceback
import re

class Built:
    def __init__(self):
        self.__name__ = 'Built'

    def run_ssh(self, sshc):
        version = ''

        try:
            data = sshc.run_command("show version")
            #print(data)  # Debug
            
            match = re.search(r'Built by:\s*(.+)', data)
            if match:
                version = match.group(1)
                print(f"[+] VyOS Build Detected: {version}")
                return version
            else:
                raise Exception("No valid build was found in the command output.")

        except Exception:
            print(traceback.format_exc())
            return None
