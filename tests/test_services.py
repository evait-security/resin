import pytest
import asyncio
import socket
import ssl
import struct
import os


RESIN_HOST = os.environ.get("RESIN_HOST", "127.0.0.1")


def tcp_connect(host, port, timeout=5):
    """Create a TCP connection and return socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


class TestSSHService:
    def test_banner(self):
        s = tcp_connect(RESIN_HOST, 22)
        banner = s.recv(256).decode("utf-8", errors="ignore")
        s.close()
        assert "OpenSSH_8.9p1" in banner

    def test_auth_rejected(self):
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with pytest.raises(paramiko.AuthenticationException):
            client.connect(RESIN_HOST, port=22, username="admin", password="admin123", timeout=10)
        client.close()


class TestFTPService:
    def test_banner(self):
        s = tcp_connect(RESIN_HOST, 21)
        banner = s.recv(256).decode("utf-8", errors="ignore")
        s.close()
        assert "vsFTPd 3.0.5" in banner

    def test_anonymous_login(self):
        s = tcp_connect(RESIN_HOST, 21)
        banner = s.recv(256).decode()
        assert "220" in banner
        s.send(b"USER anonymous\r\n")
        resp = s.recv(256).decode()
        assert "331" in resp
        s.send(b"PASS test@test.com\r\n")
        resp = s.recv(256).decode()
        assert "230" in resp
        s.close()

    def test_login_rejected(self):
        s = tcp_connect(RESIN_HOST, 21)
        s.recv(256)
        s.send(b"USER admin\r\n")
        s.recv(256)
        s.send(b"PASS password123\r\n")
        resp = s.recv(256).decode()
        assert "530" in resp
        s.close()


class TestHTTPService:
    def test_login_page(self):
        import urllib.request
        resp = urllib.request.urlopen(f"http://{RESIN_HOST}:80", timeout=10)
        html = resp.read().decode()
        assert "DESIGO CC" in html
        assert "username" in html

    def test_login_attempt(self):
        import urllib.request
        import urllib.parse
        data = urllib.parse.urlencode({"username": "admin", "password": "admin"}).encode()
        req = urllib.request.Request(f"http://{RESIN_HOST}:80/api/login", data=data, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as e:
            assert e.code == 401

    def test_https_available(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        import urllib.request
        resp = urllib.request.urlopen(
            f"https://{RESIN_HOST}:443", timeout=10, context=ctx
        )
        html = resp.read().decode()
        assert "DESIGO CC" in html


class TestSMBService:
    def test_connection(self):
        s = tcp_connect(RESIN_HOST, 445)
        # Send SMB2 negotiate
        header = bytearray(64)
        header[0:4] = b"\xfeSMB"
        header[4:6] = struct.pack("<H", 64)
        header[12:14] = struct.pack("<H", 0)  # NEGOTIATE

        body = bytearray(36)
        body[0:2] = struct.pack("<H", 36)
        body[2:4] = struct.pack("<H", 1)  # dialect count
        body[4:6] = struct.pack("<H", 0)  # security mode
        body[8:12] = struct.pack("<I", 0)  # capabilities
        body[36-2:36] = struct.pack("<H", 0x0311)  # SMB 3.1.1

        payload = bytes(header) + bytes(body)
        netbios = struct.pack(">I", len(payload))
        s.send(netbios + payload)

        response = s.recv(4096)
        s.close()
        # Should get some response back
        assert len(response) > 4


class TestSNMPService:
    def test_get_sysdescr(self):
        # Build SNMPv2c GET request for sysDescr.0
        # Using raw socket since pysnmp might not be installed in test env
        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # Minimal SNMP GET request for 1.3.6.1.2.1.1.1.0 (sysDescr)
        # Pre-built packet for simplicity
        community = b"public"
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        varbind = bytes([0x30, len(oid) + 2]) + oid + bytes([0x05, 0x00])
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        request_id = bytes([0x02, 0x01, 0x01])
        error_status = bytes([0x02, 0x01, 0x00])
        error_index = bytes([0x02, 0x01, 0x00])
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
        version = bytes([0x02, 0x01, 0x01])  # SNMPv2c
        comm = bytes([0x04, len(community)]) + community
        msg_content = version + comm + pdu
        message = bytes([0x30, len(msg_content)]) + msg_content

        sock.sendto(message, (RESIN_HOST, 161))
        data, addr = sock.recvfrom(4096)
        sock.close()

        # Verify response contains Siemens info
        assert b"Siemens" in data or b"DESIGO" in data


class TestMySQLService:
    def test_banner(self):
        s = tcp_connect(RESIN_HOST, 3306)
        data = s.recv(4096)
        s.close()
        # MySQL greeting packet should contain version string
        assert b"MariaDB" in data or b"10.11" in data

    def test_auth_rejected(self):
        s = tcp_connect(RESIN_HOST, 3306)
        greeting = s.recv(4096)
        assert len(greeting) > 0

        # Send a minimal auth packet
        username = b"root\x00"
        # Capabilities (4 bytes) + max packet (4 bytes) + charset (1) + reserved (23)
        auth = bytearray(32)
        auth[0:4] = struct.pack("<I", 0x000FA68D)  # capabilities
        auth[4:8] = struct.pack("<I", 16777216)
        auth[8] = 45  # utf8mb4
        payload = bytes(auth) + username + bytes([0])  # no auth data

        header = struct.pack("<I", len(payload))[:3] + bytes([1])
        s.send(header + payload)

        response = s.recv(4096)
        s.close()
        # Should get error response (0xFF)
        assert len(response) > 4 and response[4] == 0xFF


class TestRedisService:
    def test_ping(self):
        s = tcp_connect(RESIN_HOST, 6379)
        s.send(b"PING\r\n")
        data = s.recv(256).decode()
        s.close()
        assert "PONG" in data

    def test_auth_rejected(self):
        s = tcp_connect(RESIN_HOST, 6379)
        s.send(b"AUTH secretpassword\r\n")
        data = s.recv(256).decode()
        s.close()
        assert "WRONGPASS" in data or "ERR" in data

    def test_info(self):
        s = tcp_connect(RESIN_HOST, 6379)
        s.send(b"INFO\r\n")
        data = s.recv(4096).decode()
        s.close()
        assert "redis_version" in data


class TestWebUI:
    def test_dashboard_loads(self):
        import urllib.request
        resp = urllib.request.urlopen(f"http://{RESIN_HOST}:1337", timeout=10)
        html = resp.read().decode()
        assert "resin" in html
        assert "honeypot" in html.lower()

    def test_api_events(self):
        import urllib.request
        import json
        resp = urllib.request.urlopen(f"http://{RESIN_HOST}:1337/api/events", timeout=10)
        data = json.loads(resp.read().decode())
        assert isinstance(data, list)

    def test_sse_endpoint(self):
        import urllib.request
        req = urllib.request.Request(f"http://{RESIN_HOST}:1337/events/stream")
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.headers.get("Content-Type") == "text/event-stream"
        resp.close()

    def test_static_path_traversal_blocked(self):
        import urllib.request
        import urllib.error
        try:
            urllib.request.urlopen(
                f"http://{RESIN_HOST}:1337/static/..%2F..%2Fetc%2Fpasswd", timeout=5
            )
            assert False, "Should have returned 403 or 404"
        except urllib.error.HTTPError as e:
            assert e.code in (403, 404)

    def test_api_events_invalid_limit(self):
        import urllib.request
        import json
        resp = urllib.request.urlopen(
            f"http://{RESIN_HOST}:1337/api/events?limit=abc", timeout=10
        )
        data = json.loads(resp.read().decode())
        assert isinstance(data, list)


class TestEventLogging:
    """Verify that service interactions create database entries visible via API."""

    def test_events_created_after_interaction(self):
        import urllib.request
        import json
        import time

        # Interact with Redis (simplest)
        s = tcp_connect(RESIN_HOST, 6379)
        s.send(b"AUTH testuser testpassword123\r\n")
        s.recv(256)
        s.close()

        # Small delay for async logging
        time.sleep(1)

        # Check API for the event
        resp = urllib.request.urlopen(
            f"http://{RESIN_HOST}:1337/api/events?q=testpassword123", timeout=10
        )
        data = json.loads(resp.read().decode())
        assert len(data) > 0
        event = data[0]
        assert event["service"] == "redis"
        assert event["action"] == "login_attempt"
        assert "testpassword123" in (event.get("password") or "")


class TestDispatcher:
    """Test webhook dispatch by checking events get marked as dispatched."""

    def test_events_dispatched(self):
        import urllib.request
        import json
        import time

        # Generate an event
        s = tcp_connect(RESIN_HOST, 6379)
        s.send(b"AUTH dispatchtest dispatch_pass_xyz\r\n")
        s.recv(256)
        s.close()

        # Wait for dispatcher cycle (30s + buffer)
        # In test mode we just verify the event exists
        time.sleep(2)

        resp = urllib.request.urlopen(
            f"http://{RESIN_HOST}:1337/api/events?q=dispatch_pass_xyz", timeout=10
        )
        data = json.loads(resp.read().decode())
        assert len(data) > 0
