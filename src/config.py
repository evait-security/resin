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
WHITELIST_FILE = os.environ.get("WHITELIST_FILE", "/data/whitelist.txt")
WHITELIST_RELOAD_INTERVAL = int(os.environ.get("WHITELIST_RELOAD_INTERVAL", "60"))
WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "1337"))
SSH_HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY_PATH", "/data/ssh_host_key")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/data/tls_cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/data/tls_key.pem")
# Writable in-container location used to generate SSH/TLS keys when the
# preferred path (typically the /data volume) is not writable, e.g. when the
# volume is root-owned or the container root FS is read-only. Keys stored here
# are not persisted across container rebuilds, which is acceptable: they are
# regenerated on the next boot.
KEY_FALLBACK_DIR = os.environ.get("KEY_FALLBACK_DIR", "/tmp")
