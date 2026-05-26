import os


WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://resin@/resin?host=/var/run/postgresql",
)
DISPATCH_INTERVAL = int(os.environ.get("DISPATCH_INTERVAL", "30"))
WEB_PORT = int(os.environ.get("WEB_PORT", "1337"))
SSH_HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY_PATH", "/data/ssh_host_key")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/data/tls_cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/data/tls_key.pem")
