import traceback
import re

class Ports:
    def __init__(self):
        self.__name__ = 'Ports'

        # PORTS:
        # |---------------------------------------------|
        # | 22    | TCP     | SSH / SFTP                |
        # | 23    | TCP     | TELNET                    |
        # | 53    | TCP/UDP | DNS                       |
        # | 80    | TCP     | HTTP                      |
        # | 443   | TCP     | HTTPS / DoH               |
        # | 123   | UDP     | NTP                       |
        # | 8080  | TCP     | HTTP-API                  |
        # |---------------------------------------------|
        # | 20    | TCP     | FTP (control)             |
        # | 21    | TCP     | FTP (data)                |
        # | 50    | IP      | ESP                       |
        # | 161   | UDP     | SNMP (general)            |
        # | 162   | UDP     | SNMP (traps)              |
        # | 500   | UDP     | IKE                       |
        # | 514   | UDP     | Syslog                    |
        # | 853   | TCP     | DoT (DNS)                 |
        # | 1194  | UDP     | OpenVPN (official port)   |
        # | 1195  | UDP     | OpenVPN (site-to-site)    |
        # | 4500  | UDP     | NAT-T                     |
        # | 1500  | UDP     | IPSec+IKEv2               |
        # | 1723  | TCP     | PPTP                      |
        # | 1701  | TCP     | L2TP                      |
        # | 51820 | UDP     | Wireguard                 |
        # |---------------------------------------------|
        # | 5001  | TCP/UDP | iperf / iperf2            |
        # | 5201  | TCP/UDP | iperf3                    |
        # |---------------------------------------------|
        # | 4789  | UDP     | VXLAN (linux based)       |
        # | 8472  | UDP     | VXLAN (vyos)              |
        # |---------------------------------------------|
        # | 3128  | TCP     | WebProxy                  |
        # | 389   | TCP     | LDAP (unencrypted)        |
        # | 636   | TCP     | LDAPS (encrypted)         |
        # |---------------------------------------------|
        # | 1812  | UDP     | Radius (authentication)   |
        # | 1813  | UDP     | Radius (accounting)       |
        # | 1645  | UDP     | Radius (legacy)           |
        # | 1646  | UDP     | Radius (legacy)           |
        # |---------------------------------------------|
        # | 6343  | TCP     | Zebra / FRRouting         |
        # |---------------------------------------------|

        self.default_ports = {
            'ssh': 22,
            'telnet': 23,
            'dns': 53,
            'http': 80,
            'https': 443,
            'ntp': 123,
            'ftp-control': 20,
            'ftp-data': 21,
            'snmp': 161,
            'snmp-trap': 162,
            'ike': 500,
            'syslog': 514,
            'dot': 853,
            'openvpn': 1194,
            'openvpn-s2s': 1195,
            'nat-t': 4500,
            'ipsec-ikev2': 1500,
            'pptp': 1723,
            'l2tp': 1701,
            'wireguard': 51820,
            'iperf': 5001,
            'iperf3': 5201,
            'vxlan-linux': 4789,
            'vxlan-vyos': 8472,
            'webproxy': 3128,
            'ldap': 389,
            'ldaps': 636,
            'radius-auth': 1812,
            'radius-acct': 1813,
            'radius-legacy1': 1645,
            'radius-legacy2': 1646,
            'frrouting': 6343,
        }

    def run_ssh(self, sshc):
        try:
            raw_config = sshc.run_command("show configuration commands | match port")
            sus_ports, recommendation = self.check_results_ssh(raw_config)
            return {
                'raw_data': raw_config,
                'suspicious': sus_ports,
                'recommendation': recommendation
            }

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, config):

        suspicious = []
        recommendation = []

        for line in config.splitlines():

            line = line.strip()

            if not line or 'firewall' in line or 'traffic-policy' in line or 'nat' in line:
                continue

            match = re.search(r"port(?: '| )(\d{1,5})", line)
            if match:
                port = int(match.group(1))
                if port <= 65535:
                    for svc, def_port in self.default_ports.items():
                        if port == def_port:
                            suspicious.append(f"Port {port} found in configuration — possible default port for {svc}")
                            match svc:
                                case "ssh":
                                    recommendation.append("Port 22 (SSH default) is in use. It is recommended to change it for obfuscation and security.")
                                case "telnet":
                                    recommendation.append("Telnet (port 23) is insecure and should be disabled.")
                                case "snmp":
                                    recommendation.append("SNMP (port 161) is exposed. Ensure it is secured or disabled if not used. Restrict access and use SNMPv3 if possible.")
                                case "snmp-trap":
                                    recommendation.append("SNMP trap port 162. Ensure traps are filtered and secured.")
                                case "openvpn":
                                    recommendation.append("OpenVPN is running on default port 1194. Consider using a custom port.")
                                case "openvpn-s2s":
                                    recommendation.append("OpenVPN is running on default port 1195. This port was seen on the vyos example wiki. Consider using a custom port.")
                                case "ike":
                                    recommendation.append(f"IPSec is running on default port {port}. This is expected but monitor for exposure.")
                                case "nat-t":
                                    recommendation.append(f"IPSec is running on default port {port}. This is expected but monitor for exposure.")
                                case "radius-auth":
                                    recommendation.append("RADIUS (auth) on default port 1812. Ensure communication is encrypted.")
                                case "radius-acct":
                                    recommendation.append("RADIUS (acct) on default port 1813. Ensure communication is encrypted.")
                                case "l2tp":
                                    recommendation.append("L2TP on port 1701. Verify tunnel security settings.")
                                case "dns":
                                    recommendation.append("DNS on port 53. Ensure no open resolver is exposed.")
                                case _:
                                    print(f"[!] Error! Correct system configuration could not be retrieved.")

        return suspicious, recommendation
