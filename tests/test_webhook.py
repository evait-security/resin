"""
Full integration test that spins up a webhook listener and verifies
the dispatcher sends batched events to it.
"""
import asyncio
import json
import socket
import threading
import time
import os
import pytest
from http.server import HTTPServer, BaseHTTPRequestHandler


RESIN_HOST = os.environ.get("RESIN_HOST", "127.0.0.1")
WEBHOOK_PORT = int(os.environ.get("TEST_WEBHOOK_PORT", "9999"))

received_payloads = []


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body)
            received_payloads.append(payload)
        except json.JSONDecodeError:
            pass
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass  # Suppress output


@pytest.fixture(scope="module")
def webhook_server():
    server = HTTPServer(("0.0.0.0", WEBHOOK_PORT), WebhookHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.mark.skipif(
    not os.environ.get("TEST_WEBHOOK_ENABLED"),
    reason="Set TEST_WEBHOOK_ENABLED=1 and configure WEBHOOK_URL to run dispatcher tests"
)
class TestWebhookDispatch:
    def test_webhook_receives_events(self, webhook_server):
        received_payloads.clear()

        # Generate events by interacting with services
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((RESIN_HOST, 6379))
        s.send(b"AUTH webhook_test_user webhook_test_pass\r\n")
        s.recv(256)
        s.close()

        # Wait for dispatch cycle
        time.sleep(35)

        assert len(received_payloads) > 0
        payload = received_payloads[-1]
        assert payload["source"] == "resin"
        assert "events" in payload
        assert isinstance(payload["events"], list)
        assert payload["count"] > 0

        # Verify event structure
        found = False
        for event in payload["events"]:
            if event.get("password") == "webhook_test_pass":
                found = True
                assert event["service"] == "redis"
                assert event["action"] == "login_attempt"
                assert "timestamp" in event
                break
        assert found, "Expected event not found in webhook payload"
