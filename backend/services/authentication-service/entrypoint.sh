#!/bin/sh
set -e

echo "Applying database migrations..."
python -m alembic upgrade head

exec uvicorn app.main:app --host 0.0.0.0 --port 8001