import asyncio
import os
from src.database import log_event
from src.mac_lookup import get_mac_for_ip


BANNER = "220 (vsFTPd 3.0.5)\r\n"

FAKE_FILES = {
    "firmware_v2.4.1.bin": 1024,
    "config_backup_2026.tar.gz": 512,
    "maintenance_log.txt": 186,
    "README": 112,
}


class FTPSession:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.peername = writer.get_extra_info("peername")
        self.ip = self.peername[0] if self.peername else "unknown"
        self.port = self.peername[1] if self.peername else 0
        self.mac = get_mac_for_ip(self.ip)
        self.username = None
        self.authenticated = False
        self.cwd = "/"

    async def send(self, msg):
        self.writer.write((msg + "\r\n").encode())
        await self.writer.drain()

    async def handle(self):
        await log_event(
            service="ftp",
            source_ip=self.ip,
            source_port=self.port,
            action="connection",
            mac_address=self.mac,
        )

        self.writer.write(BANNER.encode())
        await self.writer.drain()

        try:
            while True:
                data = await asyncio.wait_for(self.reader.readline(), timeout=120)
                if not data:
                    break
                line = data.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                await self.handle_command(cmd, arg)

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self.writer.close()

    async def handle_command(self, cmd, arg):
        if cmd == "USER":
            self.username = arg
            await log_event(
                service="ftp",
                source_ip=self.ip,
                source_port=self.port,
                action="user_command",
                username=arg,
                mac_address=self.mac,
            )
            await self.send("331 Please specify the password.")

        elif cmd == "PASS":
            password = arg
            if self.username and self.username.lower() == "anonymous":
                self.authenticated = True
                await log_event(
                    service="ftp",
                    source_ip=self.ip,
                    source_port=self.port,
                    action="login_success",
                    username=self.username,
                    password=password,
                    mac_address=self.mac,
                    data={"note": "anonymous access granted"},
                )
                await self.send("230 Login successful.")
            else:
                await log_event(
                    service="ftp",
                    source_ip=self.ip,
                    source_port=self.port,
                    action="login_attempt",
                    username=self.username,
                    password=password,
                    mac_address=self.mac,
                )
                await self.send("530 Login incorrect.")

        elif cmd == "SYST":
            await self.send("215 UNIX Type: L8")

        elif cmd == "FEAT":
            await self.send("211-Features:")
            await self.send(" UTF8")
            await self.send(" PASV")
            await self.send(" SIZE")
            await self.send("211 End")

        elif cmd == "PWD":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                await self.send(f'257 "{self.cwd}" is the current directory')

        elif cmd == "TYPE":
            await self.send("200 Switching to Binary mode.")

        elif cmd == "PASV":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                await self.send("425 Use PORT or PASV first.")

        elif cmd == "LIST" or cmd == "NLST":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                await log_event(
                    service="ftp",
                    source_ip=self.ip,
                    source_port=self.port,
                    action="list_command",
                    username=self.username,
                    mac_address=self.mac,
                    data={"path": arg or self.cwd},
                )
                await self.send("150 Here comes the directory listing.")
                await self.send("226 Directory send OK.")

        elif cmd == "SIZE":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                fname = arg.strip("/")
                if fname in FAKE_FILES:
                    await self.send(f"213 {FAKE_FILES[fname]}")
                else:
                    await self.send("550 Could not get file size.")

        elif cmd == "RETR":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                await log_event(
                    service="ftp",
                    source_ip=self.ip,
                    source_port=self.port,
                    action="file_download",
                    username=self.username,
                    mac_address=self.mac,
                    data={"filename": arg},
                )
                await self.send("425 Use PORT or PASV first.")

        elif cmd == "STOR":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                await log_event(
                    service="ftp",
                    source_ip=self.ip,
                    source_port=self.port,
                    action="file_upload_attempt",
                    username=self.username,
                    mac_address=self.mac,
                    data={"filename": arg},
                )
                await self.send("550 Permission denied.")

        elif cmd == "QUIT":
            await self.send("221 Goodbye.")

        elif cmd == "NOOP":
            await self.send("200 NOOP ok.")

        elif cmd == "CWD":
            if not self.authenticated:
                await self.send("530 Please login with USER and PASS.")
            else:
                await self.send("250 Directory successfully changed.")

        elif cmd == "PORT":
            await self.send("200 PORT command successful.")

        else:
            await log_event(
                service="ftp",
                source_ip=self.ip,
                source_port=self.port,
                action="unknown_command",
                username=self.username,
                mac_address=self.mac,
                data={"command": cmd, "args": arg},
            )
            await self.send("502 Command not implemented.")


async def start_ftp_service(host="0.0.0.0", port=21):
    async def handle_client(reader, writer):
        session = FTPSession(reader, writer)
        await session.handle()

    server = await asyncio.start_server(handle_client, host, port)
    print(f"[resin] FTP service listening on {host}:{port}")
    return server
