import asyncio
import threading
import logging
import os
import re
import sys
import traceback
import tempfile

from impacket.smbserver import SimpleSMBServer

from src.database import log_event
from src.mac_lookup import get_mac_for_ip


# Regex to parse impacket's NTLM auth log lines
# Format: "user::domain:challenge:response:response"
NTLM_HASH_RE = re.compile(r"^(.+?)::(.+?):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)")
AUTH_MSG_RE = re.compile(r"AUTHENTICATE_MESSAGE \((.+?)\\(.+?),(.+?)\)")


class CredentialHandler(logging.Handler):
    """Intercepts impacket's credential logging and writes to our database."""

    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        self._connections = {}  # thread_id -> (ip, port)
        self._last_ip = "unknown"
        self._last_port = 0

    def emit(self, record):
        msg = self.format(record)
        thread_id = threading.current_thread().ident

        # Capture connection info
        conn_match = re.search(r"Incoming connection \((\d+\.\d+\.\d+\.\d+),(\d+)\)", msg)
        if conn_match:
            ip = conn_match.group(1)
            port = int(conn_match.group(2))
            self._connections[thread_id] = (ip, port)
            self._last_ip = ip
            self._last_port = port
            mac = get_mac_for_ip(ip)
            asyncio.run_coroutine_threadsafe(
                log_event(
                    service="smb",
                    source_ip=ip,
                    source_port=port,
                    action="connection",
                    mac_address=mac,
                ),
                self.loop,
            )
            return

        # Resolve IP from thread-local state, fallback to last known
        ip, port = self._connections.get(thread_id, (self._last_ip, self._last_port))

        # Capture NTLM auth messages
        auth_match = AUTH_MSG_RE.search(msg)
        if auth_match:
            domain = auth_match.group(1)
            username = auth_match.group(2)
            workstation = auth_match.group(3)
            mac = get_mac_for_ip(ip)
            display_user = f"{domain}\\{username}" if domain else username

            asyncio.run_coroutine_threadsafe(
                log_event(
                    service="smb",
                    source_ip=ip,
                    source_port=port,
                    action="ntlm_auth",
                    username=display_user,
                    mac_address=mac,
                    data={
                        "domain": domain,
                        "username": username,
                        "workstation": workstation,
                        "auth_type": "NTLMv2",
                    },
                ),
                self.loop,
            )
            return

        # Capture NTLMv2 hash lines (user::domain:challenge:response:response)
        hash_match = NTLM_HASH_RE.match(msg)
        if hash_match:
            username = hash_match.group(1)
            domain = hash_match.group(2)
            mac = get_mac_for_ip(ip)
            ntlm_hash = msg.strip()

            asyncio.run_coroutine_threadsafe(
                log_event(
                    service="smb",
                    source_ip=ip,
                    source_port=port,
                    action="ntlm_hash_captured",
                    username=f"{domain}\\{username}" if domain else username,
                    password=ntlm_hash,
                    mac_address=mac,
                    data={"ntlmv2_hash": ntlm_hash},
                ),
                self.loop,
            )
            return


async def start_smb_service(host="0.0.0.0", port=445):
    loop = asyncio.get_event_loop()

    # Set up credential capture via impacket's logging
    handler = CredentialHandler(loop)
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Impacket uses "impacket" and "impacket.smbserver" loggers
    for logger_name in ("impacket", "impacket.smbserver"):
        logger = logging.getLogger(logger_name)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    # Suppress impacket's "SMB2 not supported, fallbacking" traceback spam
    # (it uses exceptions for control flow, the fallback works fine)
    _original_print_exc = traceback.print_exc

    def _filtered_print_exc(*args, **kwargs):
        exc = sys.exc_info()[1]
        if exc and "SMB2 not supported" in str(exc):
            return
        _original_print_exc(*args, **kwargs)

    traceback.print_exc = _filtered_print_exc

    # Create temp share directory with fake building automation files
    share_path = tempfile.mkdtemp(prefix="resin_smb_")
    for fname in ["config_backup_2026.bak", "schedules.db", "alarms.log"]:
        with open(os.path.join(share_path, fname), "w") as f:
            f.write("")

    def run_server():
        server = SimpleSMBServer(
            listenAddress=host,
            listenPort=port,
        )
        server.setSMB2Support(True)
        server.addShare("BACKUP$", share_path, "Building Automation Backup")
        server.setSMBChallenge("")

        # Patch the internal SMBSERVER instance to use our persona
        # (SimpleSMBServer generates random names and processConfigFile already ran)
        srv = server._SimpleSMBServer__server
        srv._SMBSERVER__serverName = "DESIGO-BMS01"
        srv._SMBSERVER__serverDomain = "BUILDING"
        srv._SMBSERVER__serverOS = "Windows 10 Enterprise 19045"

        server.start()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    print(f"[resin] SMB service listening on {host}:{port}")
    return thread
