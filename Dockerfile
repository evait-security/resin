FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
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

EXPOSE 21 22 80 443 445 1337 3306 6379
EXPOSE 161/udp

CMD ["python", "-m", "src.main"]
