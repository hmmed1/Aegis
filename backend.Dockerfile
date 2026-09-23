# syntax=docker/dockerfile:1

# ---------- build stage ----------
FROM python:3.12-slim AS builder

WORKDIR /build
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- runtime stage ----------
FROM python:3.12-slim

RUN useradd --create-home --uid 1000 aegis
WORKDIR /app

COPY --from=builder /install /usr/local
COPY backend/app ./app

USER aegis
EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
