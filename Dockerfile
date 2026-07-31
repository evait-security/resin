# ── Stage 1: builder ─────────────────────────────────────────────────────────
# :latest-dev ships apk/pip/sh; same Wolfi Python package as :latest so
# compiled wheels (asyncpg, cryptography, aiohttp) have the exact right ABI.
FROM cgr.dev/chainguard/python:latest-dev AS builder

USER root
WORKDIR /app

COPY requirements.txt .
# --copies produces real ELF binaries in venv/bin so setcap can target them
# directly without touching the system Python or requiring --copies workarounds
# in the production image.
RUN python -m venv --copies /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY assets/ assets/
# Pre-compile to avoid write attempts against the read-only root FS at runtime
RUN /app/venv/bin/python3 -m compileall -q src/ assets/ 2>/dev/null || true

# chown first (chown clears file caps), then setcap so the nonroot process
# (uid 65532) can bind ports < 1024.  Requires cap_add: NET_BIND_SERVICE in
# docker-compose so the capability remains in the bounding set.
RUN apk add --no-cache libcap-utils && \
    chown -R 65532:65532 /app && \
    setcap 'cap_net_bind_service=+eip' "$(readlink -f /app/venv/bin/python3)"

# ── Stage 2: test ─────────────────────────────────────────────────────────────
# Retains Debian-slim + shell + pytest + paramiko + tests/ for CI.
# Build with: docker compose -f docker-compose.test.yml up --build
FROM python:3.12-slim AS test

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pytest paramiko

COPY src/ src/
COPY assets/ assets/
COPY tests/ tests/
COPY init.sql .

CMD ["python", "-m", "src.main"]

# ── Stage 3: production ───────────────────────────────────────────────────────
# Wolfi distroless: only Python + venv + src/ + assets/.
# No shell, no busybox, no package manager, no curl/wget, no coreutils.
# Runs as nonroot (uid 65532).
# Privileged ports via file capability on the venv Python binary (set in
# builder stage); cap_add: NET_BIND_SERVICE keeps it in the bounding set.
# security_opt: no-new-privileges is intentionally omitted — it suppresses
# file capabilities on exec, which is the mechanism we rely on here.
FROM cgr.dev/chainguard/python:latest AS production

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# No --chown: ownership (65532) and security.capability xattr are already set
# correctly in the builder stage. --chown would clear the file capability.
COPY --from=builder /app/venv /app/venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/assets /app/assets

EXPOSE 21 22 80 443 445 1337 3306 6379
EXPOSE 161/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/venv/bin/python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:1337/', timeout=4)"]

ENTRYPOINT ["/app/venv/bin/python3"]
CMD ["-m", "src.main"]
