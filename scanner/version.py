import traceback
import re

class Version:
    def __init__(self):
        self.__name__ = 'Version'

    def run_ssh(self, sshc):
        version = ''

        try:
            data = sshc.run_command("show version")

            match = re.search(r'Version:\s*VyOS\s+([\w\.\-]+)', data)
            if match:
                version = match.group(1)

                result = self.check_results_ssh(version)
                if result:
                    return {
                        'raw_data': version,
                        'release_name': result['release_name'],
                        'support_status': result['support_status'],
                        'recommendation': result['recommendation']
                    }

            raise Exception("No valid version was found in the command output.")

        except Exception:
            print(traceback.format_exc())
            return None

    def check_results_ssh(self, version):
        status = {
            '1.0': ('Hydrogen', 'Unsupported', 'End of Life'),
            '1.1': ('Helium', 'Unsupported', 'End of Life'),
            '1.2': ('Crux', 'Unsupported', 'End of Life'),
            '1.3': ('Equuleus', 'Unsupported', 'End of Life in April 2025'),
            '1.4': ('Sagitta', 'Supported', 'Maintenance and security release - supported until 2028'),
            '1.5': ('Circinus', 'Supported', 'Development branch - supported until 2028')
        }

        try:
            version_clean = version.strip().lower()

            # Detect new rolling/nightly (format YYYY.MM.DD-xxxx-rolling)
            if re.match(r'\d{4}\.\d{2}\.\d{2}-\d{4}-rolling', version_clean):
                return {
                    'release_name': 'Nightly Build',
                    'support_status': 'Rolling',
                    'raw_data': version,
                    'recommendation': (
                        f"Version {version} is a nightly build. Nightly builds are not recommended for production "
                        f"environments. Consider switching to a supported LTS release like 1.4 (Sagitta) or 1.5 (Circinus)."
                    )
                }

            # Detect old rolling/nightly (format N.N-rolling-YYYYMMDD)
            if re.match(r'1\.\d+-rolling-\d{8}', version_clean):
                base_version = version_clean.split('-')[0]
                if base_version in status:
                    release_name, _, _ = status[base_version]
                else:
                    release_name = 'Unknown'

                return {
                    'release_name': f'{release_name} Rolling',
                    'support_status': 'Rolling',
                    'raw_data': version,
                    'recommendation': (
                        f"Version {version} is a rolling release. Rolling versions are meant for testing and development, "
                        f"not for stable environments. It's recommended to use an official LTS release."
                    )
                }

            # Detect Stream releases (format N.N-stream or YYYY.MM)
            if re.match(r'1\.\d+-stream', version_clean) or re.match(r'20\d{2}\.\d{2}', version_clean):
                base_match = re.search(r'(1\.\d+)', version_clean)
                if base_match and base_match.group(1) in status:
                    release_name = f"{status[base_match.group(1)][0]} Stream"
                else:
                    release_name = 'Stream Release'
                    
                return {
                    'release_name': release_name,
                    'support_status': 'Stream',
                    'raw_data': version,
                    'recommendation': (
                        f"Version {version} is a Stream release. Stream versions are early-access milestones "
                        f"between rolling and LTS releases. They are suitable for testing upcoming features but "
                        f"are generally not recommended for mission-critical production environments."
                    )
                }

            # Detect official versions
            version_match = re.match(r'(\d+\.\d+)', version_clean)
            if version_match:
                base_version = version_match.group(1)

                if base_version in status:
                    release_name, support_status, comment = status[base_version]

                    supported_versions = [
                        f"{ver} ({status[ver][0]})"
                        for ver in sorted(status)
                        if status[ver][1] == 'Supported'
                    ]

                    if support_status == 'Unsupported':
                        recommendation = (
                            f"Version {version} ({release_name}) is no longer officially supported. "
                            f"It is recommended to upgrade to a supported version: {', '.join(supported_versions)}."
                        )
                    else:
                        recommendation = (
                            f"Version {version} ({release_name}) is supported. {comment}"
                        )

                    return {
                        'release_name': release_name,
                        'support_status': support_status,
                        'raw_data': version,
                        'recommendation': recommendation
                    }

            return {
                'release_name': 'Unknown',
                'support_status': 'Unknown',
                'raw_data': version,
                'recommendation': 'Support status of this release could not be determined.'
            }

        except Exception:
            print(traceback.format_exc())
            return None
