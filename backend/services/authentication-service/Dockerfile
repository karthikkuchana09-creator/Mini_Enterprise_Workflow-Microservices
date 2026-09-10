FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY shared /app/shared
COPY services/authentication-service /app/authentication-service
COPY services/tenant-service /app/tenant-service
COPY services/notification-service /app/notification-service

RUN pip install --no-cache-dir -r /app/authentication-service/requirements.txt

WORKDIR /app/authentication-service

ENV PYTHONPATH=/app/shared:/app/authentication-service:/app/tenant-service:/app/notification-service

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')" || exit 1

COPY services/authentication-service/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]