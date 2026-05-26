<p align="center">
  <img src="assets/logo.svg" width="80" alt="resin">
</p>

<h1 align="center">resin</h1>

<p align="center">
  Network service honeypot that captures attacker interactions and delivers them to your webhook.
</p>

<p align="center">
  <a href="https://github.com/evait-security/resin">github.com/evait-security/resin</a>
</p>

---

## What is this

resin deploys a set of realistic network services that look like a building automation controller sitting on your network. When someone touches these services (port scans, login attempts, data exfiltration), every interaction gets logged with full detail and pushed to your webhook endpoint as JSON.

It runs entirely in Docker. No agents, no cloud dependencies. Clone, configure one environment variable, and start the containers.

### The trap

From the outside, resin looks like a Siemens DESIGO CC building automation system. It exposes FTP (firmware updates), SSH (management), HTTP/HTTPS (web panel), SMB (backup share), SNMP (monitoring), MySQL (application database), and Redis (cache). Every service responds with realistic banners and behavior. None of them grant actual access.

### What gets captured

Every TCP connection, every authentication attempt, every command sent to these services gets written to PostgreSQL with:

- Source IP and port
- MAC address (when available via ARP)
- Service name and action type
- Credentials (username + password in cleartext)
- Full interaction data (headers, commands, payloads)
- Timestamps

Every 30 seconds, pending events get batched into a single HTTP POST and sent to your webhook URL as JSON.

---

## Installation

### Prerequisites

- Linux system with Docker and Docker Compose
- Port 22 available (you need to move your real SSH first)

### Step 1: Move your SSH port

resin uses port 22 for the SSH honeypot. Move your real SSH to a different port first.

Edit your SSH daemon config:

```bash
sudo nano /etc/ssh/sshd_config
```

Find the line `#Port 22` (or `Port 22`) and change it:

```
Port 2222
```

If your system uses a socket-based activation (systemd), also check:

```bash
sudo systemctl edit ssh.socket
```

And override the `ListenStream`:

```ini
[Socket]
ListenStream=
ListenStream=2222
```

Apply the change:

```bash
# For systems using ssh.service directly:
sudo systemctl restart sshd

# For systems using ssh.socket (Ubuntu 22.04+, Debian 12+):
sudo systemctl restart ssh.socket
```

Verify you can still connect on the new port before continuing:

```bash
ssh -p 2222 user@your-server
```

Update your firewall rules if applicable:

```bash
sudo ufw allow 2222/tcp
sudo ufw deny 22/tcp
```

### Step 2: Clone and configure

```bash
git clone https://github.com/evait-security/resin.git
cd resin
cp .env.example .env
```

Edit `.env` and set your webhook URL:

```bash
nano .env
```

```
WEBHOOK_URL=https://your-endpoint.example.com/webhook
```

### Step 3: Start

```bash
docker compose up -d
```

That is it. Services are live. Events flow to your webhook.

### Verify

```bash
docker compose ps
docker compose logs -f resin
```

Test from another machine:

```bash
ssh admin@your-honeypot-ip
curl http://your-honeypot-ip
```

Check the dashboard (only accessible from the host itself):

```bash
curl http://127.0.0.1:1337
```

For remote dashboard access, use an SSH tunnel:

```bash
ssh -p 2222 -L 1337:127.0.0.1:1337 user@your-server
```

Then open `http://localhost:1337` in your browser.

---

## Services

| Port | Protocol | Persona | Behavior |
|------|----------|---------|----------|
| 21 | FTP | vsFTPd 3.0.5 | Anonymous read-only with fake firmware files. Logs all login attempts. |
| 22 | SSH | OpenSSH 8.9p1 Ubuntu | Accepts connections, logs credentials, always denies access. |
| 80 | HTTP | Siemens DESIGO CC v5.0 | Building automation login page. Logs all requests and POST credentials. |
| 443 | HTTPS | Siemens DESIGO CC v5.0 | Same as HTTP with self-signed TLS (Siemens cert subject). |
| 445 | SMB | SMB 3.1.1 | Responds to negotiate, logs NTLM auth attempts. Denies access. |
| 161/udp | SNMP | Siemens building controller | Responds to GET/GETNEXT with realistic OIDs. Logs community strings. |
| 3306 | MySQL | MariaDB 10.11.6 | Sends handshake, logs auth attempts, returns access denied. |
| 6379 | Redis | Redis 7.2.4 | Responds to PING/INFO, logs AUTH attempts, denies everything else. |
| 1337 | HTTP | Dashboard | Live event viewer. Localhost only. |

---

## Webhook Payload

Every 30 seconds (configurable via `DISPATCH_INTERVAL`), resin sends a POST request:

```json
{
  "source": "resin",
  "dispatched_at": "2026-05-26T14:30:00.000Z",
  "count": 3,
  "events": [
    {
      "id": 42,
      "service": "ssh",
      "source_ip": "192.168.1.100",
      "source_port": 54321,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "action": "login_attempt",
      "username": "root",
      "password": "toor",
      "data": {"method": "password"},
      "timestamp": "2026-05-26T14:29:45.123Z"
    },
    {
      "id": 43,
      "service": "http",
      "source_ip": "10.0.0.5",
      "source_port": 49152,
      "mac_address": null,
      "action": "login_attempt",
      "username": "admin",
      "password": "admin",
      "data": {
        "method": "POST",
        "path": "/api/login",
        "user_agent": "Mozilla/5.0"
      },
      "timestamp": "2026-05-26T14:29:47.456Z"
    }
  ]
}
```

Events are marked as dispatched after successful delivery (HTTP 2xx). Failed deliveries are retried on the next cycle.

---

## Dashboard

The web interface at `http://127.0.0.1:1337` provides:

- Live event stream (Server-Sent Events, updates every 2 seconds)
- Service filter dropdown
- Full-text search across IPs, usernames, passwords, and actions
- Expandable event details showing raw interaction data
- Color-coded service indicators

No authentication required. The port is bound to localhost only. Use SSH tunneling for remote access.

---

## Architecture

```
                    attacker
                       |
        +--------------+--------------+
        |              |              |
     port 22       port 80       port 445 ...
        |              |              |
+-------+----------------------------+-------+
|                  resin container            |
|                                            |
|   asyncio event loop                       |
|   +-- SSH service (asyncssh)              |
|   +-- FTP service (custom protocol)       |
|   +-- HTTP/S service (aiohttp)            |
|   +-- SMB service (custom protocol)       |
|   +-- SNMP service (custom UDP)           |
|   +-- MySQL service (custom protocol)     |
|   +-- Redis service (custom protocol)     |
|   +-- Webhook dispatcher (30s loop)       |
|   +-- Web dashboard (:1337)               |
|                    |                       |
+--------------------+-----------------------+
                     |
              unix socket (no TCP, no auth)
                     |
              +------+------+
              |  PostgreSQL  |
              |   (events)   |
              +--------------+
                     |
              webhook POST
                     |
              your endpoint
```

All services run in a single Python process using asyncio. Events are logged directly to PostgreSQL via a shared Unix socket (no TCP, no passwords). The dispatcher uses `SELECT ... FOR UPDATE SKIP LOCKED` to batch pending events without contention, making the database act as a concurrent job queue without Redis or RabbitMQ.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_URL` | (empty) | HTTP endpoint for event delivery. Leave empty to disable. |
| `DISPATCH_INTERVAL` | `30` | Seconds between webhook batch sends. |

---

## Network Mode

resin runs with `network_mode: host` so it can read the host's ARP table for real client MAC addresses. The web dashboard binds exclusively to `127.0.0.1:1337` — it is never exposed to the network.

---

## Running Tests

The test suite validates that every service responds correctly, logs events to the database, and the web dashboard serves data. Tests run inside Docker against the live stack.

### Quick run (inside running containers)

If you already have `docker compose up -d` running:

```bash
docker compose exec resin pytest /app/tests/ -v
```

### Full isolated test run

Spins up a fresh stack with a dedicated test runner container:

```bash
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

### What gets tested

| Test class | What it validates |
|------------|-------------------|
| `TestSSHService` | Banner matches OpenSSH 8.9p1, password auth is rejected via paramiko |
| `TestFTPService` | vsFTPd banner, anonymous login succeeds, non-anonymous login rejected |
| `TestHTTPService` | DESIGO CC login page loads, POST credentials return 401, HTTPS works |
| `TestSMBService` | SMB2 negotiate handshake completes |
| `TestSNMPService` | sysDescr GET returns Siemens building controller string |
| `TestMySQLService` | MariaDB banner in handshake, auth packet returns error |
| `TestRedisService` | PING/PONG, AUTH rejected with WRONGPASS, INFO returns version |
| `TestWebUI` | Dashboard HTML loads, /api/events returns JSON array, SSE endpoint streams |
| `TestEventLogging` | Redis AUTH attempt appears in /api/events within 1 second |
| `TestDispatcher` | Events exist in database after interaction |

### Webhook dispatch test

`tests/test_webhook.py` contains a full-cycle test that starts an HTTP server, triggers events, and waits for the dispatcher to POST them. Requires `TEST_WEBHOOK_ENABLED=1` and the webhook URL pointed at the test listener:

```bash
docker compose exec resin pytest /app/tests/test_webhook.py -v \
  --override-ini="env=TEST_WEBHOOK_ENABLED=1"
```

---

## Development

```bash
docker compose up -d postgres
pip install -r requirements.txt
python -m src.main
```

Run tests locally (requires services to be running):

```bash
pip install pytest paramiko
RESIN_HOST=127.0.0.1 pytest tests/ -v
```

---

## License

MIT. See [LICENSE](LICENSE).

Built by [evait security](https://github.com/evait-security).