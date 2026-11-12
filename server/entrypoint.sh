#!/bin/sh
set -eu

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "[entrypoint] Running Alembic database migrations..."
    alembic upgrade head
fi

echo "[entrypoint] Starting Tactical RMM Control Plane..."
exec "$@"
