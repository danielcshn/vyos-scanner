import traceback
import re

class System:
    def __init__(self):
        self.__name__ = 'System'

    def run_ssh(self, sshc):
        try:
            data = {
                'df': sshc.run_command("df -h"),
                'memory': sshc.run_command("show system memory"),
                'uptime': sshc.run_command("show system uptime")
            }

            return self.check_results_ssh(data)

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, data):
        df_data = data.get('df', '')
        memory_data = data.get('memory', '')
        uptime_data = data.get('uptime', '')

        suspicious = []
        recommendation = []

        for line in df_data.splitlines():
            if line.startswith("Filesystem") or not line.strip():
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            fs = parts[0]
            size = parts[1]
            used = parts[2]
            avail = parts[3]
            use_percent = parts[4]
            mount = ' '.join(parts[5:])

            try:
                percent = int(use_percent.strip('%'))
                if percent > 90:
                    suspicious.append(f"[!] Partition with high usage: {fs} ({use_percent}) on {mount}")
                    recommendation.append(f"Check space usage on {mount} ({fs})")
            except:
                continue

        try:
            lines = memory_data.splitlines()
            mem = {}
            for line in lines:
                if ':' in line:
                    k, v = line.split(':', 1)
                    mem[k.strip().lower()] = int(v.strip())

            total = mem.get('total', 0)
            used = mem.get('used', 0)
            if total > 0 and used / total > 0.85:
                suspicious.append(f"[!] High RAM usage: {used}/{total} MB")
                recommendation.append("Review processes that are consuming memory")
        except:
            pass

        if uptime_data:
            uptime_data = data.get("uptime", "")
            if uptime_data:
                match = re.search(
                    r"up\s+((\d+)\s+days?,\s+)?(\d+):(\d+),\s+(\d+)\s+users?,\s+load average:\s+([\d\.]+),\s+([\d\.]+),\s+([\d\.]+)",
                    uptime_data
                )
                if match:
                    days = int(match.group(2)) if match.group(2) else 0
                    hours = int(match.group(3))
                    minutes = int(match.group(4))
                    users = int(match.group(5))
                    load_1 = float(match.group(6))
                    load_5 = float(match.group(7))
                    load_15 = float(match.group(8))

                    total_uptime = f"{days}d {hours}h {minutes}m"
                    load_str = f"{load_1:.2f}, {load_5:.2f}, {load_15:.2f}"
                    status = []

                    if days == 0 and hours < 6:
                        status.append("[!] Possible recent reboot")

                    elif days >= 30:
                        status.append("[!] System with high stability (30+ days of uptime)")

                    if load_1 > 1.0 and load_5 > 1.0 and load_15 > 1.0:
                        status.append("[!] High average system load")

                    summary = "; ".join(status) if status else "General system status acceptable"

                    recommendation.append(
                        f"Uptime: {total_uptime} | Users: {users} | Load average (1/5/15): {load_str}\n→ {summary}"
                    )

                    if status:
                        suspicious.append("Uptime requiere atención")

        if not suspicious:
            suspicious.append("System without critical alerts")

        return {
            'raw_data': data,
            'suspicious': '\n'.join(suspicious),
            'recommendation': recommendation
        }
