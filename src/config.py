import os


WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://resin@/resin?host=/var/run/postgresql",
)

DISPATCH_INTERVAL = int(os.environ.get("DISPATCH_INTERVAL", "30"))
# Comma/space separated list of IPs and CIDR ranges that are completely
# ignored: connections are dropped at the earliest possible point and no
# events are generated.
WHITELIST_IPS = os.environ.get("WHITELIST_IPS", "")
# Newline/comma separated list of regular expressions. Each pattern is
# evaluated against the source IP string of every request; a match causes the
# connection to be dropped just like a whitelisted IP. Kept separate from
# WHITELIST_IPS to avoid mixing exact IP/CIDR matching with regex matching.
WHITELIST_IP_MASK = os.environ.get("WHITELIST_IP_MASK", "")
WHITELIST_FILE = os.environ.get("WHITELIST_FILE", "/data/whitelist.txt")
WHITELIST_RELOAD_INTERVAL = int(os.environ.get("WHITELIST_RELOAD_INTERVAL", "60"))
WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "1337"))
SSH_HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY_PATH", "/data/ssh_host_key")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/data/tls_cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/data/tls_key.pem")
