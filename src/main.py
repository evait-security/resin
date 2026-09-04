import asyncio
import signal
import sys

from src.config import WEBHOOK_URL, DISABLED_SERVICES
from src.database import init_pool, close_pool
from src.dispatcher import dispatch_loop
from src.web.server import start_web_server
from src.services.ssh import start_ssh_service
from src.services.ftp import start_ftp_service
from src.services.http import start_http_service, start_https_service
from src.services.smb import start_smb_service
from src.services.snmp import start_snmp_service
from src.services.mysql import start_mysql_service
from src.services.redis import start_redis_service
from src.whitelist import load_whitelist, watch_whitelist


async def wait_for_postgres():
    """Wait until PostgreSQL is reachable."""
    import asyncpg
    from src.config import POSTGRES_DSN

    for attempt in range(30):
        try:
            conn = await asyncpg.connect(POSTGRES_DSN)
            await conn.close()
            return
        except (OSError, asyncpg.exceptions.ConnectionDoesNotExistError,
                asyncpg.exceptions.CannotConnectNowError, Exception):
            print(f"[resin] Waiting for PostgreSQL... ({attempt + 1}/30)")
            await asyncio.sleep(2)

    print("[resin] Could not connect to PostgreSQL after 60 seconds")
    sys.exit(1)


async def main():
    print("[resin] Starting honeypot services...")
    print(f"[resin] Webhook URL: {WEBHOOK_URL or 'NOT CONFIGURED'}")
    load_whitelist()

    await wait_for_postgres()
    await init_pool()

    # Start all services (except those disabled via DISABLED_SERVICES)
    services = []
    disabled = []

    service_defs = [
        ("ssh", "ssh:22", start_ssh_service),
        ("http", "http:80", start_http_service),
        ("https", "https:443", start_https_service),
        ("smb", "smb:445", start_smb_service),
        ("snmp", "snmp:161", start_snmp_service),
        ("mysql", "mysql:3306", start_mysql_service),
        ("redis", "redis:6379", start_redis_service),
        ("web", "web:1337", start_web_server),
        ("ftp", "ftp:21", start_ftp_service),
    ]

    for name, label, starter in service_defs:
        if name in DISABLED_SERVICES:
            disabled.append(label)
            continue
        try:
            await starter()
            services.append(label)
        except Exception as e:
            print(f"[resin] {name.upper()} failed to start: {e}")

    if disabled:
        print(f"[resin] Disabled services: {', '.join(disabled)}")

    print(f"[resin] Active services: {', '.join(services)}")

    # Start dispatcher and whitelist watcher as background tasks
    tasks = [
        asyncio.create_task(dispatch_loop()),
        asyncio.create_task(watch_whitelist()),
    ]

    # Keep running
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    loop.add_signal_handler(signal.SIGHUP, load_whitelist)

    await stop.wait()

    print("[resin] Shutting down...")
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await close_pool()


if __name__ == "__main__":
    asyncio.run(main())