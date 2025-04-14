import traceback
import re
from passlib.hash import sha512_crypt, md5_crypt

class Users:
    def __init__(self):
        self.__name__ = 'Users'

    def run_ssh(self, sshc):
        version = ''

        try:
            data = sshc.run_command("show configuration commands | match encrypted-password")
            #print(data)  # Debug

            lines = data.strip().splitlines()
            raw_data = '\n'.join([line for line in lines if 'authentication' in line])

            users_with_password_vyos = []
            users = self.extract_users_and_passwords(data)

            for user, encrypted in users:
                if self.is_default_vyos_password(encrypted):
                    users_with_password_vyos.append(user)

            if users_with_password_vyos:
                suspicious = (
                    f"They met {len(users_with_password_vyos)} user(s) "
                    f"with the default password 'vyos': {', '.join(users_with_password_vyos)}"
                )
                recommendation = (
                    f"Change the default password for the following users: "
                    f"{', '.join(users_with_password_vyos)}"
                )
            else:
                suspicious = "No users were found with the default password 'vyos'."
                recommendation = "No action required."

            return {
                'raw_data': raw_data.strip(),
                'suspicious': suspicious,
                'recommendation': recommendation
            }

        except Exception:
            print(traceback.format_exc())
            return None

    def extract_users_and_passwords(self, config_output):
        pattern = r"set system login user (\S+) authentication encrypted-password '([^']+)'"
        return re.findall(pattern, config_output)

    def is_default_vyos_password(self, encrypted_password):
        try:
            if encrypted_password.startswith("$6$"):
                return sha512_crypt.verify("vyos", encrypted_password)
            elif encrypted_password.startswith("$1$"):
                return md5_crypt.verify("vyos", encrypted_password)
            else:
                return False
        except Exception as e:
            print(f"[!] Error verifying hash: {e}")
            return False