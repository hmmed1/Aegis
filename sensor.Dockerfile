# syntax=docker/dockerfile:1

# ---------- build stage ----------
FROM python:3.12-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
COPY sensors/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- runtime stage ----------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /install /usr/local
COPY sensors/run.py .

ENV PYTHONUNBUFFERED=1

# The container needs to run with NET_ADMIN + NET_RAW capabilities (or
# network_mode: host, as in docker-compose.yml) for scapy to capture and
# ARP-sweep on the host's real interfaces. It intentionally runs as root
# because raw sockets require it even with the capabilities granted.
CMD ["python", "run.py"]
