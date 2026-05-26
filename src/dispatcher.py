import asyncio
import json
import aiohttp
from datetime import datetime
from src.config import WEBHOOK_URL, DISPATCH_INTERVAL
from src.database import fetch_pending, mark_dispatched


async def dispatch_loop():
    """Every DISPATCH_INTERVAL seconds, batch pending events and POST to webhook."""
    print(f"[resin] Dispatcher started (interval={DISPATCH_INTERVAL}s, url={WEBHOOK_URL or 'NOT SET'})")

    while True:
        await asyncio.sleep(DISPATCH_INTERVAL)

        if not WEBHOOK_URL:
            continue

        try:
            rows = await fetch_pending(limit=500)
            if not rows:
                continue

            events = []
            event_ids = []
            for row in rows:
                event = {
                    "id": row["id"],
                    "service": row["service"],
                    "source_ip": str(row["source_ip"]),
                    "source_port": row["source_port"],
                    "mac_address": row["mac_address"],
                    "action": row["action"],
                    "username": row["username"],
                    "password": row["password"],
                    "data": json.loads(row["data"]) if isinstance(row["data"], str) else row["data"],
                    "timestamp": row["created_at"].isoformat(),
                }
                events.append(event)
                event_ids.append(row["id"])

            payload = {
                "source": "resin",
                "dispatched_at": datetime.utcnow().isoformat() + "Z",
                "count": len(events),
                "events": events,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    WEBHOOK_URL,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"Content-Type": "application/json", "User-Agent": "resin/1.0"},
                ) as resp:
                    if resp.status < 300:
                        await mark_dispatched(event_ids)
                        print(f"[resin] Dispatched {len(events)} events (HTTP {resp.status})")
                    else:
                        print(f"[resin] Webhook returned {resp.status}, will retry")

        except Exception as e:
            print(f"[resin] Dispatch error: {e}")
