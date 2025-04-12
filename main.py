import argparse

from scanner.sshclient import SSHClient

from scanner.version import Version
from scanner.built import Built

def main(args):
    all_data = {}
    commands = [Version(), Built()]

    print(f'** VyOS ip address: {args.ip}\n')

    ssh_client = SSHClient(args.ip, args.username, args.password, int(args.port))
    ssh_client.connect()
    
    for command in commands:
        res = command.run_ssh(ssh_client)
        all_data[command.__name__] = res
    
    ssh_client.disconnect()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='The tested VyOS IP address', required=True)
    parser.add_argument('-p', '--port', help='The tested VyOS SSH port', default='22')
    parser.add_argument('-u', '--username', help='User name with admin Permissions', required=True)
    parser.add_argument('-ps', '--password', help='The password of the given user name', default='')
    args = parser.parse_args()

    main(args)
