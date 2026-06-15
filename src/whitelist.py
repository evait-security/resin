import os
import asyncio
import ipaddress

from src.config import WHITELIST_IPS, WHITELIST_FILE, WHITELIST_RELOAD_INTERVAL

_WHITELIST_NETWORKS: list = []
_last_mtime: float | None = None


def _parse_whitelist(raw: str) -> list:
    """Parse a newline/comma/space separated list of IPs and CIDR networks.

    Lines and inline suffixes starting with # are treated as comments and
    ignored. Invalid entries are skipped with a warning.
    """
    networks = []
    for line in raw.splitlines():
        line = line.split("#")[0].strip()   # inline- und full-line-Kommentare entfernen
        if not line:
            continue
        for entry in line.replace(",", " ").split():
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                print(f"[resin] Ungültiger Whitelist-Eintrag ignoriert: {entry!r}")
    return networks


def load_whitelist() -> None:
    """Load or reload the whitelist from file or environment variable.

    WHITELIST_FILE takes precedence over WHITELIST_IPS. If the file is
    missing or unreadable, WHITELIST_IPS is used as a fallback. Updates
    _WHITELIST_NETWORKS in-place so all callers see the new state immediately.
    """
    global _last_mtime
    raw = ""
    if WHITELIST_FILE and os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE) as f:
                raw = f.read()
            _last_mtime = os.path.getmtime(WHITELIST_FILE)
        except OSError as e:
            print(f"[resin] Whitelist nicht lesbar: {e}")
    else:
        _last_mtime = None
    _WHITELIST_NETWORKS[:] = _parse_whitelist(raw or WHITELIST_IPS)
    if _WHITELIST_NETWORKS:
        print(f"[resin] Whitelist: {', '.join(str(n) for n in _WHITELIST_NETWORKS)}")


def is_whitelisted(ip: str) -> bool:
    """Return True if the given IP is on the configured whitelist.

    Whitelisted IPs are dropped at the earliest possible point in each
    service and never generate events.
    """
    if not _WHITELIST_NETWORKS or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _WHITELIST_NETWORKS)


async def watch_whitelist() -> None:
    """Asyncio background task that reloads the whitelist when the file changes.

    Polls WHITELIST_FILE every WHITELIST_RELOAD_INTERVAL seconds and calls
    load_whitelist() if the mtime has changed. Runs indefinitely alongside
    the main event loop and should be started with asyncio.create_task().
    """
    while True:
        await asyncio.sleep(WHITELIST_RELOAD_INTERVAL)
        try:
            if os.path.getmtime(WHITELIST_FILE) != _last_mtime:
                load_whitelist()
        except (OSError, TypeError):
            if _last_mtime is not None:
                print("[resin] Whitelist-Datei entfernt, lade Fallback")
                load_whitelist()