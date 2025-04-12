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

            match = re.search(r'Version:\s*VyOS\s+([0-9]+\.[0-9]+\.[0-9]+)', data)
            if match:
                version = match.group(1)
                print(f"[+] VyOS version detected: {version}")
                return version
            else:
                raise Exception("No valid version was found in the command output.")

        except Exception:
            print(traceback.format_exc())
            return None
