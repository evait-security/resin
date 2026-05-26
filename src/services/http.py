import ssl
import os
from aiohttp import web
from src.database import log_event
from src.mac_lookup import get_mac_for_ip
from src.config import TLS_CERT_PATH, TLS_KEY_PATH

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DESIGO CC - Building Automation</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.login-container { background: #16213e; border-radius: 8px; padding: 40px; width: 380px; box-shadow: 0 4px 24px rgba(0,0,0,0.4); }
.logo { text-align: center; margin-bottom: 24px; }
.logo h1 { font-size: 18px; color: #00b4d8; font-weight: 400; letter-spacing: 1px; }
.logo h2 { font-size: 13px; color: #666; margin-top: 4px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 12px; color: #999; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
.form-group input { width: 100%; padding: 10px 12px; background: #0f3460; border: 1px solid #1a4a7a; border-radius: 4px; color: #fff; font-size: 14px; }
.form-group input:focus { outline: none; border-color: #00b4d8; }
.btn { width: 100%; padding: 12px; background: #00b4d8; color: #fff; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; text-transform: uppercase; letter-spacing: 1px; }
.btn:hover { background: #0096c7; }
.footer { text-align: center; margin-top: 20px; font-size: 11px; color: #555; }
</style>
</head>
<body>
<div class="login-container">
<div class="logo">
<h1>DESIGO CC</h1>
<h2>Building Automation Platform</h2>
</div>
<form method="POST" action="/api/login">
<div class="form-group">
<label>Username</label>
<input type="text" name="username" autocomplete="off" required>
</div>
<div class="form-group">
<label>Password</label>
<input type="password" name="password" required>
</div>
<button class="btn" type="submit">Sign In</button>
</form>
<div class="footer">Siemens DESIGO CC v5.0 &mdash; &copy; Siemens AG 2026</div>
</div>
</body>
</html>"""

LOGIN_FAILED_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DESIGO CC - Authentication Failed</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.container { background: #16213e; border-radius: 8px; padding: 40px; width: 380px; text-align: center; }
.error { color: #e63946; margin-bottom: 16px; }
a { color: #00b4d8; text-decoration: none; }
</style>
</head>
<body>
<div class="container">
<p class="error">Authentication failed. Invalid credentials.</p>
<a href="/">Return to login</a>
</div>
</body>
</html>"""


async def handle_index(request):
    ip = request.remote
    port = request.transport.get_extra_info("peername")[1] if request.transport else 0
    mac = get_mac_for_ip(ip)
    await log_event(
        service="http",
        source_ip=ip,
        source_port=port,
        action="page_request",
        mac_address=mac,
        data={
            "method": request.method,
            "path": str(request.path),
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", ""),
        },
    )
    return web.Response(text=LOGIN_PAGE, content_type="text/html")


async def handle_login(request):
    ip = request.remote
    port = request.transport.get_extra_info("peername")[1] if request.transport else 0
    mac = get_mac_for_ip(ip)

    try:
        post_data = await request.post()
        username = post_data.get("username", "")
        password = post_data.get("password", "")
    except Exception:
        username = ""
        password = ""

    await log_event(
        service="http",
        source_ip=ip,
        source_port=port,
        action="login_attempt",
        username=username,
        password=password,
        mac_address=mac,
        data={
            "method": "POST",
            "path": "/api/login",
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", ""),
        },
    )
    return web.Response(text=LOGIN_FAILED_PAGE, content_type="text/html", status=401)


async def handle_any(request):
    ip = request.remote
    port = request.transport.get_extra_info("peername")[1] if request.transport else 0
    mac = get_mac_for_ip(ip)

    body = ""
    try:
        body = await request.text()
    except Exception:
        pass

    await log_event(
        service="http",
        source_ip=ip,
        source_port=port,
        action="page_request",
        mac_address=mac,
        data={
            "method": request.method,
            "path": str(request.path),
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", ""),
            "body": body[:4096] if body else None,
        },
    )

    if "admin" in str(request.path).lower() or "api" in str(request.path).lower():
        return web.Response(
            text='{"error":"unauthorized","code":401}',
            content_type="application/json",
            status=401,
        )
    return web.Response(text=LOGIN_PAGE, content_type="text/html")


def generate_self_signed_cert():
    if os.path.exists(TLS_CERT_PATH) and os.path.exists(TLS_KEY_PATH):
        return
    os.makedirs(os.path.dirname(TLS_CERT_PATH), exist_ok=True)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "desigo-cc.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Siemens AG"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Building Technologies"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )

    with open(TLS_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(TLS_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _create_app():
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_post("/api/login", handle_login)
    app.router.add_route("*", "/{path:.*}", handle_any)
    return app


async def start_http_service(host="0.0.0.0", port=80):
    app = _create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[resin] HTTP service listening on {host}:{port}")


async def start_https_service(host="0.0.0.0", port=443):
    generate_self_signed_cert()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)

    app = _create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port, ssl_context=ssl_ctx)
    await site.start()
    print(f"[resin] HTTPS service listening on {host}:{port}")
