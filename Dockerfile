FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc libcap2-bin curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir paramiko pytest

COPY src/ src/
COPY assets/ assets/
COPY tests/ tests/
COPY init.sql .

RUN mkdir -p /data

# Allow non-root to bind privileged ports
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/python3.12

# Run as non-root user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/false appuser && \
    chown -R appuser:appgroup /app /data

USER appuser

EXPOSE 21 22 80 443 445 1337 3306 6379
EXPOSE 161/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:1337/ || exit 1

CMD ["python", "-m", "src.main"]
