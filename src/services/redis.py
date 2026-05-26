import asyncio
from src.database import log_event
from src.mac_lookup import get_mac_for_ip


REDIS_VERSION = "7.2.4"

REDIS_INFO = f"""# Server
redis_version:{REDIS_VERSION}
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:a1b2c3d4e5f6g7h8
redis_mode:standalone
os:Linux 5.15.0-91-generic x86_64
arch_bits:64
monotonic_clock:POSIX clock_gettime
multiplexing_api:epoll
tcp_port:6379
server_time_usec:1716700800000000
uptime_in_seconds:864000
uptime_in_days:10
hz:10
configured_hz:10
lru_clock:16777215
executable:/usr/local/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
cluster_connections:0
maxclients:10000

# Memory
used_memory:1048576
used_memory_human:1.00M
used_memory_rss:2097152
used_memory_rss_human:2.00M
used_memory_peak:2097152
used_memory_peak_human:2.00M
total_system_memory:8589934592
total_system_memory_human:8.00G
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction

# Stats
total_connections_received:142
total_commands_processed:1893
"""


def encode_error(msg):
    return f"-ERR {msg}\r\n".encode()


def encode_simple_string(msg):
    return f"+{msg}\r\n".encode()


def encode_bulk_string(msg):
    if msg is None:
        return b"$-1\r\n"
    data = msg.encode() if isinstance(msg, str) else msg
    return f"${len(data)}\r\n".encode() + data + b"\r\n"


def encode_integer(val):
    return f":{val}\r\n".encode()


def parse_redis_command(data):
    """Parse RESP protocol command."""
    try:
        text = data.decode("utf-8", errors="ignore").strip()
        if not text:
            return []

        # Inline command
        if not text.startswith("*"):
            return text.split()

        # RESP array
        lines = text.split("\r\n")
        if not lines:
            return []

        count = int(lines[0][1:])
        args = []
        i = 1
        for _ in range(count):
            if i >= len(lines):
                break
            if lines[i].startswith("$"):
                i += 1
                if i < len(lines):
                    args.append(lines[i])
                i += 1
            else:
                args.append(lines[i])
                i += 1
        return args
    except (ValueError, IndexError):
        # Try inline
        return data.decode("utf-8", errors="ignore").strip().split()


class RedisHoneypot:
    def __init__(self, host="0.0.0.0", port=6379):
        self.host = host
        self.port = port
        self.authenticated = {}

    async def handle_client(self, reader, writer):
        peername = writer.get_extra_info("peername")
        ip = peername[0] if peername else "unknown"
        port = peername[1] if peername else 0
        mac = get_mac_for_ip(ip)

        await log_event(
            service="redis",
            source_ip=ip,
            source_port=port,
            action="connection",
            mac_address=mac,
        )

        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not data:
                    break

                args = parse_redis_command(data)
                if not args:
                    continue

                cmd = args[0].upper()

                if cmd == "AUTH":
                    # Redis 6+: AUTH username password
                    # Redis <6: AUTH password
                    if len(args) > 2:
                        username = args[1]
                        password = args[2]
                    else:
                        username = ""
                        password = args[1] if len(args) > 1 else ""
                    await log_event(
                        service="redis",
                        source_ip=ip,
                        source_port=port,
                        action="login_attempt",
                        username=username,
                        password=password,
                        mac_address=mac,
                        data={"command": "AUTH"},
                    )
                    writer.write(encode_error("WRONGPASS invalid username-password pair"))
                    await writer.drain()

                elif cmd == "PING":
                    writer.write(encode_simple_string("PONG"))
                    await writer.drain()

                elif cmd == "INFO":
                    section = args[1] if len(args) > 1 else "all"
                    await log_event(
                        service="redis",
                        source_ip=ip,
                        source_port=port,
                        action="info_request",
                        mac_address=mac,
                        data={"section": section},
                    )
                    writer.write(encode_bulk_string(REDIS_INFO))
                    await writer.drain()

                elif cmd == "CONFIG":
                    subcmd = args[1].upper() if len(args) > 1 else ""
                    await log_event(
                        service="redis",
                        source_ip=ip,
                        source_port=port,
                        action="config_request",
                        mac_address=mac,
                        data={"subcommand": subcmd, "args": args[2:]},
                    )
                    writer.write(encode_error("NOAUTH Authentication required"))
                    await writer.drain()

                elif cmd == "KEYS":
                    pattern = args[1] if len(args) > 1 else "*"
                    await log_event(
                        service="redis",
                        source_ip=ip,
                        source_port=port,
                        action="keys_request",
                        mac_address=mac,
                        data={"pattern": pattern},
                    )
                    writer.write(encode_error("NOAUTH Authentication required"))
                    await writer.drain()

                elif cmd == "QUIT":
                    writer.write(encode_simple_string("OK"))
                    await writer.drain()
                    break

                elif cmd == "COMMAND":
                    writer.write(encode_simple_string("OK"))
                    await writer.drain()

                else:
                    await log_event(
                        service="redis",
                        source_ip=ip,
                        source_port=port,
                        action="command",
                        mac_address=mac,
                        data={"command": cmd, "args": args[1:]},
                    )
                    writer.write(encode_error("NOAUTH Authentication required"))
                    await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        print(f"[resin] Redis service listening on {self.host}:{self.port}")
        return server


async def start_redis_service(host="0.0.0.0", port=6379):
    redis = RedisHoneypot(host, port)
    return await redis.start()
