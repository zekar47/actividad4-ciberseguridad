#!/usr/bin/env bash
# Detiene los procesos del laboratorio local (sin tocar servicios del sistema).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUN="$ROOT/.lab/run"

if [ -f "$RUN/php.pid" ]; then
  kill "$(cat "$RUN/php.pid")" 2>/dev/null || true
  rm -f "$RUN/php.pid"
fi

if [ -S "$RUN/mysql.sock" ]; then
  mariadb-admin --no-defaults --socket="$RUN/mysql.sock" -u root shutdown 2>/dev/null || true
fi
if [ -f "$RUN/mariadb.pid" ]; then
  kill "$(cat "$RUN/mariadb.pid")" 2>/dev/null || true
  rm -f "$RUN/mariadb.pid"
fi

echo "[lab] detenido"
