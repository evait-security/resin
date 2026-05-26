import asyncio
import signal
import sys

from src.config import WEBHOOK_URL
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

    await wait_for_postgres()
    await init_pool()

    # Start all services
    services = []

    try:
        await start_ssh_service()
        services.append("ssh:22")
    except Exception as e:
        print(f"[resin] SSH failed to start: {e}")

    try:
        await start_http_service()
        services.append("http:80")
    except Exception as e:
        print(f"[resin] HTTP failed to start: {e}")

    try:
        await start_https_service()
        services.append("https:443")
    except Exception as e:
        print(f"[resin] HTTPS failed to start: {e}")

    try:
        await start_smb_service()
        services.append("smb:445")
    except Exception as e:
        print(f"[resin] SMB failed to start: {e}")

    try:
        await start_snmp_service()
        services.append("snmp:161")
    except Exception as e:
        print(f"[resin] SNMP failed to start: {e}")

    try:
        await start_mysql_service()
        services.append("mysql:3306")
    except Exception as e:
        print(f"[resin] MySQL failed to start: {e}")

    try:
        await start_redis_service()
        services.append("redis:6379")
    except Exception as e:
        print(f"[resin] Redis failed to start: {e}")

    try:
        await start_web_server()
        services.append("web:1337")
    except Exception as e:
        print(f"[resin] Web UI failed to start: {e}")

    try:
        await start_ftp_service()
        services.append("ftp:21")
    except Exception as e:
        print(f"[resin] FTP failed to start: {e}")

    print(f"[resin] Active services: {', '.join(services)}")

    # Start dispatcher as a background task
    tasks = [
        asyncio.create_task(dispatch_loop()),
    ]

    # Keep running
    stop = asyncio.Event()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    await stop.wait()

    print("[resin] Shutting down...")
    for task in tasks:
        task.cancel()
    await close_pool()


if __name__ == "__main__":
    asyncio.run(main())
