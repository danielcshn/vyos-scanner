import traceback
import re
import json
import requests

class Packages:
    def __init__(self):
        self.__name__ = 'Packages'

    def run_ssh(self, sshc):
        major_version = ''
        packages_versions = ''
        raw_output = ''

        try:
            data = sshc.run_command("show version")
            match = re.search(r'Version:\s*VyOS\s+(\d+)\.(\d+)', data)
            if match:
                major_version = f"{match.group(1)}.{match.group(2)}"
                
            match major_version:
                case "1.0":
                    packages_10 = "bind9-host cluster-agents cluster-glue conntrack coreutils cron curl hostapd iperf iproute ipsec-tools iptables iptraf lldpd login net-tools ntp open-vm-tools openssh-server openssl openvpn passwd ppp pppoe pptpd rsync rsyslog snmp squid3 squidguard ssh ssmtp strongswan sudo wireshark-common wpasupplicant xz-utils libpam-radius-auth libpam-runtime"
                    command = f"dpkg-query -W -f='${{Package}},${{Version}}\\n' {packages_10}"
                    raw_output = sshc.run_command(command)
                case "1.1":
                    packages_11 = "bind9-host cluster-agents conntrack coreutils cron curl dnsmasq dnsmasq-base hostapd igmpproxy iperf iproute ipsec-tools iptables lldpd login net-tools ntp ntpdate open-vm-tools openssh-server openssl openvpn passwd ppp pppoe pptpd rsync rsyslog snmp squid3 squidclient squidguard ssh ssmtp strongswan sysv-rc sysvinit tshark ubnt-igmpproxy util-linux wireshark-common wpasupplicant xz-utils libpam-radius-auth libpam-runtime"
                    command = f"dpkg-query -W -f='${{Package}},${{Version}}\\n' {packages_11}"
                    raw_output = sshc.run_command(command)
                case "1.2":
                    packages_12 = "bind9-host busybox coreutils cron curl efibootmgr frr gawk geoip-database git grub-common hostapd iperf iperf3 iproute iproute2 iptables isc-dhcp-common isc-dhcp-server lldpd login monitoring-plugins-basic mysql-common nginx-common ntp open-vm-tools openssh-server openssl openvpn openvpn-auth-ldap openvpn-auth-radius passwd pdns-recursor qemu-guest-agent radius-shell rsync rsyslog snmp squid3 squidclient squidguard ssl-cert strongswan strongswan-charon systemd telnet tftpd-hpa wireguard wpasupplicant xz-utils"
                    command = f"dpkg-query -W -f='${{binary:Package}},${{Version}}\\n' {packages_12}"
                    raw_output = sshc.run_command(command)
                case "1.3":
                    packages_13 = "bind9-host busybox certbot curl dns-root-data dropbear dropbear-bin fastnetmon frr iperf iperf3 iproute2 iptables isc-dhcp-server nftables ntp openssh-client openssh-server openssh-sftp-server openssl openvpn passwd ppp pppoe qemu-guest-agent radius-shell rsync rsyslog snmp ssl-cert strongswan strongswan-charon sudo systemd telnet wireguard-modules wpasupplicant libpam-cap:amd64 libpam-modules:amd64 libpam-modules-bin libpam-radius-auth libpam-runtime libpam-systemd:amd64 libpam0g:amd64 login libnftables1:amd64 hostapd coreutils bash libssl1.1:amd64 libgnutls30:amd64"
                    command = f"dpkg-query -W -f='${{binary:Package}},${{Version}}\\n' {packages_13}"
                    raw_output = sshc.run_command(command)
                case "1.4":
                    packages_14 = "aardvark-dns avahi-daemon bind9-host busybox certbot chrony conntrack conserver-server coreutils cron curl dns-root-data dnsdist dosfstools dropbear fastnetmon frr git haproxy hostapd inetutils-telnet iperf iperf3 iproute2 iptables isc-dhcp-server lldpd login lua-lpeg:amd64 mariadb-common mysql-common netcat-openbsd nftables nginx openssh-server openssl openvpn openvpn-auth-ldap openvpn-auth-radius openvpn-dco openvpn-otp owamp-server passwd pdns-recursor ppp pppoe radius-shell rsync rsyslog sendmail-bin snmp squid squidguard sshguard ssl-cert sstp-client strongswan strongswan-charon systemd systemd-sysv telnet tftpd-hpa twamp-server wireguard-tools wireless-regdb wpasupplicant zabbix-agent2 zabbix-agent2-plugin-mongodb zabbix-agent2-plugin-postgresql zlib1g:amd64 zstd libgnutls30:amd64 libnftables1:amd64 libpam-cap:amd64 libpam-modules:amd64 libpam-modules-bin libpam-radius-auth libpam-runtime libpam-systemd:amd64 libpam0g:amd64"
                    command = f"dpkg-query -W -f='${{binary:Package}},${{Version}}\\n' {packages_14}"
                    raw_output = sshc.run_command(command)
                case "1.5":
                    packages_15 = "aardvark-dns bind9-host busybox certbot conntrack conserver-server coreutils cron cryptsetup curl dnsdist fastnetmon frr git gpg haproxy iperf iperf3 iproute2 iptables kea kea-dhcp4-server kea-dhcp6-server linux-base nat-rtsp netavark netcat-openbsd nftables openssh-server passwd ppp pppoe qemu-guest-agent radius-shell rsync rsyslog snmp squidguard sshguard strongswan strongswan-charon sudo systemd telnet twamp-server wget wide-dhcpv6-client wpasupplicant zabbix-agent2 libgnutls30 libnftables1 libpam-cap libpam-modules libpam-modules-bin libpam-radius-auth libpam-runtime libpam-systemd libpam0g login"
                    command = f"dpkg-query -W -f='${{binary:Package}},${{Version}}\\n' {packages_15}"
                    raw_output = sshc.run_command(command)
                case _:
                    print(f"[!] Error! Correct system version could not be retrieved.")

            lines = raw_output.strip().splitlines()
            valid_lines = []
            for line in lines:
                line = line.strip()
                # Accepts name that can have ":" and version with numbers, letters and hyphens
                if re.match(r'^[\w\-\.:]+,[\w\-\.\+\:~]+$', line):
                    valid_lines.append(line)

            packages_versions = '\n'.join(valid_lines).replace(',', ' ')
            #print(packages_versions)  # Debug

            result = self.check_results_ssh(packages_versions)
            return result
            # print(result)  # Debug

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, package_list: str):
        url = "https://api.osv.dev/v1/querybatch"

        lines = [
            line.strip() for line in package_list.strip().splitlines()
            if len(line.strip().split()) == 2
        ]

        queries = []
        for line in package_list.strip().splitlines():
            parts = line.strip().split()
            if len(parts) != 2:
                continue
            package, version = parts
            queries.append({
                "package": {
                    "name": package,
                    "ecosystem": "Debian"
                },
                "version": version
            })

        #print(queries)

        response = requests.post(url, json={"queries": queries})
        if response.status_code != 200:
            raise Exception(f"Error {response.status_code}: {response.text}")
        
        data = response.json()
        total_cves = 0
        result_cves = []

        for idx, result in enumerate(data.get("results", [])):
            if "vulns" in result and result["vulns"]:
                pkg_name, pkg_version = lines[idx].split()
                result_cves.append(f"Package Name: {pkg_name} - Versión: {pkg_version}")
                for vuln in result["vulns"]:
                    cve_id = vuln.get("id", "UNKNOWN ID")
                    modified = vuln.get("modified", "No modification date")

                    if cve_id.startswith("CVE"):
                        url = vuln.get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                    else:
                        url = vuln.get("url", f"https://security-tracker.debian.org/tracker/{cve_id}")

                    result_cves.append(f"- {cve_id}: {url} - Modified: {modified}")
                total_cves += len(result["vulns"])

        return {
            'raw_data': package_list.strip(),
            'suspicious': f'{total_cves} CVEs found',
            'recommendation': '\n'.join(result_cves) if result_cves else 'No vulnerabilities were found.'
        }