import asyncssh
import os
from src.database import log_event
from src.mac_lookup import get_mac_for_ip
from src.config import SSH_HOST_KEY_PATH


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self):
        self._conn = None

    def connection_made(self, conn):
        self._conn = conn
        peername = conn.get_extra_info("peername")
        if peername:
            self._ip = peername[0]
            self._port = peername[1]
        else:
            self._ip = "unknown"
            self._port = 0

    def connection_lost(self, exc):
        pass

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        mac = get_mac_for_ip(self._ip)
        await log_event(
            service="ssh",
            source_ip=self._ip,
            source_port=self._port,
            action="login_attempt",
            username=username,
            password=password,
            mac_address=mac,
            data={"method": "password"},
        )
        return False

    async def validate_public_key(self, username, key):
        mac = get_mac_for_ip(self._ip)
        await log_event(
            service="ssh",
            source_ip=self._ip,
            source_port=self._port,
            action="login_attempt",
            username=username,
            mac_address=mac,
            data={"method": "public_key", "key_type": key.get_algorithm()},
        )
        return False


def generate_host_key():
    if not os.path.exists(SSH_HOST_KEY_PATH):
        os.makedirs(os.path.dirname(SSH_HOST_KEY_PATH), exist_ok=True)
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(SSH_HOST_KEY_PATH)


async def start_ssh_service(host="0.0.0.0", port=22):
    generate_host_key()
    await asyncssh.create_server(
        HoneypotSSHServer,
        host,
        port,
        server_host_keys=[SSH_HOST_KEY_PATH],
        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        process_factory=None,
    )
    print(f"[resin] SSH service listening on {host}:{port}")
