#!/bin/sh
set -e

exec uvicorn tenant.main:app --host 0.0.0.0 --port 8003