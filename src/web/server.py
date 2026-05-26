import asyncio
import json
from aiohttp import web
from pathlib import Path
from src.database import get_events, get_latest_id
from src.config import WEB_PORT


STATIC_DIR = Path(__file__).parent / "static"
TEMPLATE_DIR = Path(__file__).parent / "templates"


async def handle_index(request):
    html = (TEMPLATE_DIR / "index.html").read_text()
    return web.Response(text=html, content_type="text/html")


async def handle_api_events(request):
    service = request.query.get("service", None)
    query = request.query.get("q", None)
    limit = min(int(request.query.get("limit", "200")), 1000)

    rows = await get_events(limit=limit, service=service, query=query)
    events = []
    for row in rows:
        events.append({
            "id": row["id"],
            "service": row["service"],
            "source_ip": str(row["source_ip"]),
            "source_port": row["source_port"],
            "mac_address": row["mac_address"],
            "action": row["action"],
            "username": row["username"],
            "password": row["password"],
            "data": json.loads(row["data"]) if isinstance(row["data"], str) else row["data"],
            "created_at": row["created_at"].isoformat(),
            "dispatched": row["dispatched"],
        })
    return web.json_response(events)


async def handle_event_stream(request):
    response = web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
    await response.prepare(request)

    last_id = await get_latest_id()

    try:
        while True:
            await asyncio.sleep(2)
            rows = await get_events(limit=50)
            new_events = [r for r in rows if r["id"] > last_id]

            if new_events:
                last_id = max(r["id"] for r in new_events)
                events = []
                for row in new_events:
                    events.append({
                        "id": row["id"],
                        "service": row["service"],
                        "source_ip": str(row["source_ip"]),
                        "source_port": row["source_port"],
                        "mac_address": row["mac_address"],
                        "action": row["action"],
                        "username": row["username"],
                        "password": row["password"],
                        "data": json.loads(row["data"]) if isinstance(row["data"], str) else row["data"],
                        "created_at": row["created_at"].isoformat(),
                    })

                data = json.dumps(events)
                await response.write(f"data: {data}\n\n".encode())
    except (ConnectionResetError, asyncio.CancelledError):
        pass

    return response


async def handle_static(request):
    filename = request.match_info["filename"]
    filepath = STATIC_DIR / filename
    if not filepath.exists() or not filepath.is_file():
        raise web.HTTPNotFound()
    content_type = "text/css" if filename.endswith(".css") else "application/javascript"
    return web.Response(text=filepath.read_text(), content_type=content_type)


async def handle_logo(request):
    logo_path = Path(__file__).parent.parent.parent / "assets" / "logo.svg"
    if logo_path.exists():
        return web.Response(text=logo_path.read_text(), content_type="image/svg+xml")
    raise web.HTTPNotFound()


async def start_web_server(host="0.0.0.0", port=None):
    port = port or WEB_PORT
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/events", handle_api_events)
    app.router.add_get("/events/stream", handle_event_stream)
    app.router.add_get("/static/{filename}", handle_static)
    app.router.add_get("/logo.svg", handle_logo)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[resin] Web dashboard listening on {host}:{port}")
