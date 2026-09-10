FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY shared /app/shared
COPY services/authentication-service /app/authentication-service
COPY services/tenant-service /app/tenant-service
COPY services/notification-service /app/notification-service

# Notification service runs its own uvicorn process; install the shared
# requirements as well (email-validator for EmailStr schemas, uvicorn server).
RUN pip install --no-cache-dir -r /app/authentication-service/requirements.txt \
    && pip install --no-cache-dir -r /app/notification-service/requirements.txt

WORKDIR /app/notification-service

ENV PYTHONPATH=/app/shared:/app/authentication-service:/app/tenant-service:/app/notification-service

EXPOSE 8004

COPY services/notification-service/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]