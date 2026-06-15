# syntax=docker/dockerfile:1.7
#
# Multi-stage build:
#   1. builder    – installs all Python dependencies into a venv that is
#                    ABI-compatible with the distroless production runtime.
#   2. test       – full Debian-slim image with pytest + paramiko + the
#                    tests/ tree, used by docker-compose.test.yml.
#   3. production – ultra-slim, hardened Wolfi/Chainguard distroless
#                    Python runtime. No shell, no package manager, no
#                    coreutils, no busybox – only `python` and the app.
#                    Default build target.

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------------------
# 1. Builder – install runtime dependencies into a venv that is ABI-compatible
#    with the distroless production runtime. We use Chainguard's `*-dev`
#    variant, which is the SAME image as `:latest` but with apk/sh/pip
#    available at build time. This guarantees that any compiled wheels we
#    install (asyncpg, cryptography, aiohttp, …) match the cpython ABI of
#    the distroless runtime exactly.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest-dev AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/venv/bin:$PATH"

WORKDIR /app
COPY requirements.txt .

# Install everything into a self-contained venv that we drop into the
# distroless image with a single COPY.
RUN python -m venv /app/venv \
    && pip install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# 2. Test image – contains the toolchain needed by the CI test stack
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS test

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir paramiko pytest

COPY src/ src/
COPY assets/ assets/
COPY tests/ tests/
COPY init.sql .

RUN mkdir -p /data \
    && groupadd -g 10001 appgroup \
    && useradd  -u 10001 -g appgroup -s /bin/false appuser \
    && chown -R appuser:appgroup /app /data

USER appuser

CMD ["python", "-m", "src.main"]


# ---------------------------------------------------------------------------
# 3. Production – distroless Wolfi (Chainguard) Python runtime
#
#    The image contains:
#      * the python interpreter + stdlib
#      * the resin application code
#      * the installed third-party Python packages
#    It does NOT contain:
#      * a shell (no /bin/sh, no bash, no busybox)
#      * package managers (no apt, no apk, no pip at runtime)
#      * any coreutils, debugging tools, network tools, compilers …
#    If the app is ever compromised, an attacker finds nothing but the
#    Python runtime they already have through the exploited process.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest AS production

# Chainguard distroless images run as the unprivileged `nonroot` user
# (uid/gid 65532) by default. Privileged port binding is delegated to the
# container runtime via `cap_add: [NET_BIND_SERVICE]` in compose – we do
# not patch the python binary with setcap here, both because the distroless
# image has no setcap utility and because container-level capabilities are
# cleaner and easier to audit.

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/venv/bin:$PATH"

WORKDIR /app

# Third-party Python packages, prepared in the builder stage.
COPY --from=builder --chown=nonroot:nonroot /app/venv /app/venv

# Application code. Only what is required at runtime is copied – no
# tests/, no init.sql, no build files.
COPY --chown=nonroot:nonroot src/    /app/src/
COPY --chown=nonroot:nonroot assets/ /app/assets/

EXPOSE 21 22 80 443 445 1337 3306 6379
EXPOSE 161/udp

# Healthcheck uses the python stdlib because no other binary exists in the
# image (curl/wget are intentionally absent).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:1337/',timeout=3).status==200 else 1)"]

ENTRYPOINT ["python", "-m", "src.main"]
