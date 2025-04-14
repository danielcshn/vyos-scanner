import paramiko
import time

class SSHClient:
    def __init__(self, host, username, password, port=22, key=''):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.key = key
        self.client = None
        self.shell = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not self.key:
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password,
                            look_for_keys=False, allow_agent=False)
        else:
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password,
                            look_for_keys=True, allow_agent=False, key_filename=self.key)

        self.shell = self.client.invoke_shell()

    def run_command(self, command, delay=2):
        if not self.shell:
            raise Exception("SSH shell not initialized.")
        self.shell.send(command + '\n')
        time.sleep(delay)
        output = self.shell.recv(65535).decode("utf-8")
        return output

    def disconnect(self):
        if self.client:
            self.client.close()
