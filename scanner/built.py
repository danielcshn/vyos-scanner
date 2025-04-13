import traceback
import re

class Built:
    def __init__(self):
        self.__name__ = 'Built'

    def run_ssh(self, sshc):
        built_by = ''

        try:
            data = sshc.run_command("show version")
            #print(data)  # Debug

            match = re.search(r'Built by:\s*(.+)', data)
            if match:
                built_by = match.group(1)
                #print(f"[+] VyOS Build Detected: {built_by}")

                sus, recommendation = self.check_results_ssh(built_by)
                #print(f"[!] VyOS Build Information: {sus} - {recommendation}")

                return {'raw_data': built_by,
                'suspicious': sus,
                'recommendation': recommendation}
            else:
                raise Exception("No valid build was found in the command output.")

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, built_by):
        built_by_official = [
            "maintainers@vyos.net",
            "vyos-build-action@github.com",
            "sentrium s.l.",
            "vyos networks iberia s.l.u."
        ]

        built_by_clean = built_by.strip().lower()

        for official in built_by_official:
            if official in built_by_clean:
                if "maintainers@vyos.net" in built_by_clean:
                    return "official", "It appears to be an official image, but it is very old."
                else:
                    return "official", "It appears to be an official image."

        return "unofficial", "Verified image was created by a third party. It may not be safe."
