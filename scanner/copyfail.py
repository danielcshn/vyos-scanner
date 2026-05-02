import traceback
import re

class CopyFail:
    def __init__(self):
        self.__name__ = 'CopyFail_CVE-2026-31431'

    def run_ssh(self, sshc):
        try:
            # Obtenemos la versión del kernel limpiando la salida ssh
            uname_raw = sshc.run_command("uname -r")
            uname = "Desconocido"
            match_uname = re.search(r'(\d+\.\d+\.\d+-[a-zA-Z0-9\-]+)', uname_raw)
            if match_uname:
                uname = match_uname.group(1)
            vyos_version_out = sshc.run_command("show version")
            
            vyos_version = "Desconocida"
            is_vulnerable_version = False
            
            # Extraer versión de VyOS (ej. 1.3.8, 1.4-rolling-..., 2026.03)
            match = re.search(r'Version:\s*VyOS\s+([\w\.\-]+)', vyos_version_out)
            if match:
                vyos_version = match.group(1)
                
            # Parsear major/minor para la lógica (1.4, 1.5 y Stream (20xx.xx) son vulnerables)
            if re.search(r'20\d{2}\.\d{2}', vyos_version):
                is_vulnerable_version = True
            else:
                match_maj_min = re.search(r'Version:\s*VyOS\s+(\d+)\.(\d+)', vyos_version_out)
                if match_maj_min:
                    major = int(match_maj_min.group(1))
                    minor = int(match_maj_min.group(2))
                    if major == 1 and minor >= 4:
                        is_vulnerable_version = True

            # Chequeo seguro: Abrimos el socket AF_ALG y además revisamos si existe os.splice en el Python del sistema
            check_cmd = "python3 -c \"import socket, os; s=socket.socket(38,5,0); s.bind(('aead','authencesn(hmac(sha256),cbc(aes))')); print('EXPOSED' + ('_SPLICE' if hasattr(os, 'splice') else '_NOSPLICE'))\" 2>/dev/null || echo 'SAFE'"
            exposure_raw = sshc.run_command(check_cmd)
            
            exposure = "SAFE"
            if "EXPOSED_SPLICE" in exposure_raw:
                exposure = "EXPOSED_SPLICE"
            elif "EXPOSED_NOSPLICE" in exposure_raw:
                exposure = "EXPOSED_NOSPLICE"

            return self.check_results_ssh(uname, vyos_version, is_vulnerable_version, exposure)

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, uname, vyos_version, is_vulnerable_version, exposure):
        suspicious = []
        recommendation = []

        raw_data = f"VyOS: {vyos_version} | Kernel: {uname}\nAF_ALG Exposure: {exposure}"

        if is_vulnerable_version and 'EXPOSED' in exposure:
            suspicious.append(f"[!] VyOS {vyos_version} appears to be vulnerable to CVE-2026-31431 ('Copy Fail')")
            recommendation.append(f"The kernel {uname} has the cryptographic API enabled (AF_ALG AEAD).")
            if '_SPLICE' in exposure:
                recommendation.append("[!] The local Python environment supports 'os.splice', which allows the PoC exploit to run natively.")
            else:
                recommendation.append("The local Python environment does not support 'os.splice', but the kernel is still exposed to C-based vectors.")
            recommendation.append("Mitigation: Update to a patched version of VyOS 1.4/1.5 or restrict AF_ALG socket creation.")
            
        elif 'EXPOSED' in exposure:
            recommendation.append(f"The kernel exposes AF_ALG, but VyOS {vyos_version} is not considered vulnerable to 'Copy Fail'.")
            recommendation.append("VyOS versions < 1.4.x lack os.splice in their native Python and/or operate with kernel versions prior to the vulnerability.")
            
        else:
            recommendation.append(f"The system (VyOS {vyos_version}, Kernel {uname}) does not expose the vulnerable interface (AF_ALG).")
            recommendation.append("It appears to be completely safe from the CVE-2026-31431 ('Copy Fail') vulnerability.")

        return {
            'raw_data': raw_data,
            'suspicious': suspicious,
            'recommendation': recommendation
        }
