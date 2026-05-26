import asyncpg
from src.config import POSTGRES_DSN

pool: asyncpg.Pool = None


async def init_pool():
    global pool
    pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=10)


async def close_pool():
    global pool
    if pool:
        await pool.close()


async def log_event(service: str, source_ip: str, source_port: int,
                    action: str, username: str = None, password: str = None,
                    mac_address: str = None, data: dict = None):
    import json
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO events (service, source_ip, source_port, mac_address,
               action, username, password, data)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)""",
            service, source_ip, source_port, mac_address,
            action, username, password, json.dumps(data or {}),
        )


async def fetch_pending(limit: int = 100):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, service, source_ip, source_port, mac_address,
                      action, username, password, data, created_at
               FROM events
               WHERE dispatched = FALSE
               ORDER BY created_at
               FOR UPDATE SKIP LOCKED
               LIMIT $1""",
            limit,
        )
        return rows


async def mark_dispatched(event_ids: list):
    if not event_ids:
        return
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE events SET dispatched = TRUE, dispatched_at = NOW()
               WHERE id = ANY($1::bigint[])""",
            event_ids,
        )


async def get_events(limit: int = 200, service: str = None, query: str = None):
    async with pool.acquire() as conn:
        conditions = []
        args = []
        idx = 1

        if service:
            conditions.append(f"service = ${idx}")
            args.append(service)
            idx += 1

        if query:
            conditions.append(
                f"(source_ip::text ILIKE ${idx} OR username ILIKE ${idx} "
                f"OR password ILIKE ${idx} OR action ILIKE ${idx} "
                f"OR data::text ILIKE ${idx})"
            )
            args.append(f"%{query}%")
            idx += 1

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        args.append(limit)

        rows = await conn.fetch(
            f"""SELECT id, service, source_ip, source_port, mac_address,
                       action, username, password, data, created_at, dispatched
                FROM events {where}
                ORDER BY created_at DESC
                LIMIT ${idx}""",
            *args,
        )
        return rows


async def get_latest_id():
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT COALESCE(MAX(id), 0) as max_id FROM events")
        return row["max_id"]
