import asyncio
import struct
import hashlib
import os
from src.database import log_event
from src.mac_lookup import get_mac_for_ip


SERVER_VERSION = "5.5.5-10.11.6-MariaDB"


def build_handshake_packet(connection_id):
    """Build MySQL initial handshake packet (Protocol 10)."""
    # Protocol version
    payload = bytes([10])
    # Server version (null-terminated)
    payload += SERVER_VERSION.encode() + b"\x00"
    # Connection ID
    payload += struct.pack("<I", connection_id)
    # Auth plugin data part 1 (8 bytes)
    salt1 = os.urandom(8)
    payload += salt1
    # Filler
    payload += b"\x00"
    # Capability flags (lower 2 bytes)
    capabilities = 0xF7FF
    payload += struct.pack("<H", capabilities & 0xFFFF)
    # Character set (utf8mb4)
    payload += bytes([45])
    # Status flags
    payload += struct.pack("<H", 0x0002)
    # Capability flags (upper 2 bytes)
    payload += struct.pack("<H", (capabilities >> 16) & 0xFFFF)
    # Length of auth plugin data
    payload += bytes([21])
    # Reserved (10 bytes of zeros)
    payload += b"\x00" * 10
    # Auth plugin data part 2 (at least 13 bytes)
    salt2 = os.urandom(12)
    payload += salt2 + b"\x00"
    # Auth plugin name
    payload += b"mysql_native_password\x00"

    # Packet header: length (3 bytes LE) + sequence number (1 byte)
    header = struct.pack("<I", len(payload))[:3] + bytes([0])
    return header + payload, salt1 + salt2


def build_error_packet(seq_num, code=1045, message="Access denied for user"):
    """Build MySQL ERR packet."""
    payload = bytes([0xFF])
    payload += struct.pack("<H", code)
    payload += b"#28000"
    payload += message.encode()

    header = struct.pack("<I", len(payload))[:3] + bytes([seq_num])
    return header + payload


def parse_auth_packet(data):
    """Parse client authentication response packet."""
    if len(data) < 36:
        return None, None

    # Skip packet header (4 bytes)
    offset = 4
    # Client capabilities (4 bytes)
    offset += 4
    # Max packet size (4 bytes)
    offset += 4
    # Character set (1 byte)
    offset += 1
    # Reserved (23 bytes)
    offset += 23

    # Username (null-terminated)
    username_end = data.index(b"\x00", offset) if b"\x00" in data[offset:] else len(data)
    username = data[offset:username_end].decode("utf-8", errors="ignore")
    offset = username_end + 1

    # Auth response length
    if offset < len(data):
        auth_len = data[offset]
        offset += 1
        auth_data = data[offset:offset + auth_len].hex() if auth_len > 0 else ""
    else:
        auth_data = ""

    return username, auth_data


class MySQLHoneypot:
    def __init__(self, host="0.0.0.0", port=3306):
        self.host = host
        self.port = port
        self.connection_counter = 0

    async def handle_client(self, reader, writer):
        peername = writer.get_extra_info("peername")
        ip = peername[0] if peername else "unknown"
        port = peername[1] if peername else 0
        mac = get_mac_for_ip(ip)

        self.connection_counter += 1
        conn_id = self.connection_counter

        await log_event(
            service="mysql",
            source_ip=ip,
            source_port=port,
            action="connection",
            mac_address=mac,
        )

        try:
            # Send handshake
            handshake, salt = build_handshake_packet(conn_id)
            writer.write(handshake)
            await writer.drain()

            # Read client auth response
            auth_data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not auth_data:
                return

            username, auth_hash = parse_auth_packet(auth_data)

            await log_event(
                service="mysql",
                source_ip=ip,
                source_port=port,
                action="login_attempt",
                username=username,
                mac_address=mac,
                data={
                    "auth_plugin": "mysql_native_password",
                    "auth_response_hex": auth_hash,
                },
            )

            # Send access denied
            error = build_error_packet(2, 1045,
                f"Access denied for user '{username}'@'{ip}' (using password: YES)")
            writer.write(error)
            await writer.drain()

            # Some clients retry or send queries, read those too
            try:
                extra = await asyncio.wait_for(reader.read(4096), timeout=5)
                if extra:
                    await log_event(
                        service="mysql",
                        source_ip=ip,
                        source_port=port,
                        action="post_auth_data",
                        username=username,
                        mac_address=mac,
                        data={"raw_hex": extra[:256].hex()},
                    )
            except asyncio.TimeoutError:
                pass

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        print(f"[resin] MySQL service listening on {self.host}:{self.port}")
        return server


async def start_mysql_service(host="0.0.0.0", port=3306):
    mysql = MySQLHoneypot(host, port)
    return await mysql.start()
