FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY shared /app/shared
COPY services/authentication-service /app/authentication-service
COPY services/tenant-service /app/tenant-service
COPY services/notification-service /app/notification-service

# Shared library + full dependency set. Each microservice runs its own
# uvicorn process; the service images collocate the shared `app` library
# package (config, security, exceptions, enums) whose full dependency set
# (jose, bcrypt, httpx, uvicorn, ...) is installed here.
RUN pip install --no-cache-dir -r /app/authentication-service/requirements.txt \
    && pip install --no-cache-dir -r /app/tenant-service/requirements.txt

WORKDIR /app/tenant-service

ENV PYTHONPATH=/app/shared:/app/authentication-service:/app/tenant-service:/app/notification-service

EXPOSE 8003

COPY services/tenant-service/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]