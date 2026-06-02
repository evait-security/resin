import ipaddress

from src.config import WHITELIST_IPS


def _parse_whitelist(raw):
    """Parse a comma/space separated list of IPs and CIDR networks."""
    networks = []
    for entry in raw.replace(",", " ").split():
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            print(f"[resin] Ignoring invalid whitelist entry: {entry}")
    return networks


_WHITELIST_NETWORKS = _parse_whitelist(WHITELIST_IPS)

if _WHITELIST_NETWORKS:
    print(f"[resin] Whitelist active for: "
          f"{', '.join(str(n) for n in _WHITELIST_NETWORKS)}")


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
    return any(addr in network for network in _WHITELIST_NETWORKS)
