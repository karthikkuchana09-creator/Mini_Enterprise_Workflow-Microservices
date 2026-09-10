#!/bin/sh
set -e

exec uvicorn notification.main:app --host 0.0.0.0 --port 8004