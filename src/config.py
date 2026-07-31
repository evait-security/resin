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
# Optional path to a whitelist file. Whitelisting is configured via the
# WHITELIST_IPS environment variable (.env) by default; set this only if you
# bind-mount your own file into the container.
WHITELIST_FILE = os.environ.get("WHITELIST_FILE", "")
WHITELIST_RELOAD_INTERVAL = int(os.environ.get("WHITELIST_RELOAD_INTERVAL", "60"))
WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "1337"))
# SSH host key and TLS cert/key are generated inside the container at runtime.
# They live in a writable in-container directory (the /tmp tmpfs), not a
# mounted volume: there is no need to persist them across container rebuilds,
# they are simply regenerated on the next boot.
SSH_HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY_PATH", "/tmp/ssh_host_key")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/tmp/tls_cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/tmp/tls_key.pem")
