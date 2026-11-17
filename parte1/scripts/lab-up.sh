#!/usr/bin/env bash
# Levanta el laboratorio de la parte 1 sin contenedores ni privilegios:
# MariaDB + PHP (servidor embebido) + DVWA 2.5 sobre 127.0.0.1.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LAB="$ROOT/.lab"
SRC="$LAB/src/DVWA-2.5"
WEB="$LAB/dvwa"
RUN="$LAB/run"
MYSQL="$LAB/mysql"
PORT=${DVWA_PORT:-8081}
DB_PORT=${DVWA_DB_PORT:-3307}

mkdir -p "$LAB" "$RUN" "$MYSQL" "$LAB/zap"

need() { command -v "$1" >/dev/null 2>&1 || { echo "falta $1; usa: nix develop" >&2; exit 1; }; }
need php
need mariadbd
need mariadb
need mariadb-install-db
need curl

# --- Código fuente de DVWA (pineado a la release 2.5) -------------------------
if [ ! -d "$SRC" ]; then
  echo "[lab] descargando DVWA 2.5"
  curl -fsSL -o "$LAB/dvwa-2.5.tar.gz" \
    https://github.com/digininja/DVWA/archive/refs/tags/2.5.tar.gz
  mkdir -p "$LAB/src"
  tar -xzf "$LAB/dvwa-2.5.tar.gz" -C "$LAB/src"
fi

if [ ! -d "$WEB" ]; then
  cp -a "$SRC" "$WEB"
  install -m 0644 "$WEB/config/config.inc.php.dist" "$WEB/config/config.inc.php"
fi
[ -f "$WEB/config/config.inc.php" ] || \
  install -m 0644 "$WEB/config/config.inc.php.dist" "$WEB/config/config.inc.php"

# --- MariaDB -----------------------------------------------------------------
if [ ! -d "$MYSQL/mysql" ]; then
  echo "[lab] inicializando MariaDB en $MYSQL"
  mariadb-install-db --no-defaults --datadir="$MYSQL" \
    --auth-root-authentication-method=normal --skip-test-db >/dev/null
fi

if ! mariadb-admin --no-defaults --socket="$RUN/mysql.sock" -u root ping >/dev/null 2>&1; then
  echo "[lab] arrancando MariaDB en 127.0.0.1:$DB_PORT"
  mariadbd --no-defaults --datadir="$MYSQL" --socket="$RUN/mysql.sock" \
    --port="$DB_PORT" --bind-address=127.0.0.1 --skip-name-resolve \
    --pid-file="$RUN/mariadb.pid" --log-error="$RUN/mariadb.log" &
  echo $! > "$RUN/mariadb.pid"
  for _ in $(seq 1 60); do
    mariadb-admin --no-defaults --socket="$RUN/mysql.sock" -u root ping >/dev/null 2>&1 && break
    sleep 0.5
  done
  mariadb-admin --no-defaults --socket="$RUN/mysql.sock" -u root ping >/dev/null 2>&1 || {
    echo "MariaDB no arrancó; revisa $RUN/mariadb.log" >&2; exit 1; }
fi

mariadb --no-defaults --socket="$RUN/mysql.sock" -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

# --- PHP ---------------------------------------------------------------------
if ! curl -fsS -o /dev/null "http://127.0.0.1:$PORT/login.php" 2>/dev/null; then
  echo "[lab] arrancando PHP en 127.0.0.1:$PORT"
  DB_SERVER=127.0.0.1 DB_PORT="$DB_PORT" DB_DATABASE=dvwa \
  DB_USER=dvwa DB_PASSWORD='p@ssw0rd' DEFAULT_SECURITY_LEVEL=low \
    php -d display_errors=0 -d log_errors=1 -d error_log="$RUN/php-error.log" \
      -S "127.0.0.1:$PORT" -t "$WEB" > "$RUN/php.log" 2>&1 &
  echo $! > "$RUN/php.pid"
  for _ in $(seq 1 40); do
    curl -fsS -o /dev/null "http://127.0.0.1:$PORT/login.php" 2>/dev/null && break
    sleep 0.25
  done
fi

# --- Inicialización funcional de DVWA ---------------------------------------
DVWA_URL="http://127.0.0.1:$PORT" \
DVWA_SESSION_FILE="$LAB/dvwa-session.env" \
  python3 "$ROOT/parte1/scripts/dvwa_init.py"

echo "[lab] listo. Sesión: $LAB/dvwa-session.env"
echo "[lab] siguiente: nix develop -c ./parte1/scripts/run-zap.sh"
