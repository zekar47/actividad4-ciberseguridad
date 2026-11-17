#!/usr/bin/env bash
# Ejecuta un escaneo autenticado de DVWA con OWASP ZAP (Automation Framework).
# La sesión se inyecta con las variables ZAP_AUTH_* documentadas por ZAP.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LAB="$ROOT/.lab"
EVIDENCE="$ROOT/parte1/evidence"

command -v zap >/dev/null 2>&1 || { echo "falta zap; usa: nix develop" >&2; exit 1; }
[ -f "$LAB/dvwa-session.env" ] || {
  echo "no hay sesión DVWA; ejecuta primero parte1/scripts/lab-up.sh" >&2; exit 1; }

# shellcheck disable=SC1091
. "$LAB/dvwa-session.env"

mkdir -p "$EVIDENCE" "$LAB/zap/home"
rm -f "$EVIDENCE/zap-report.html" "$EVIDENCE/zap-report.json"

# ZAP aplica esta cabecera a todas las peticiones (autenticación "manual").
export ZAP_AUTH_HEADER=Cookie
export ZAP_AUTH_HEADER_VALUE="$DVWA_COOKIE"
export ZAP_AUTH_HEADER_SITE=127.0.0.1

cd "$EVIDENCE"
echo "[zap] escaneando http://127.0.0.1:8081 (puede tardar varios minutos)"
# HOME aislado: el wrapper de Nix crea allí un config.xml escribible.
# Sesión nueva en cada ejecución para no arrastrar el árbol de sitios anterior.
env HOME="$LAB/zap/home" zap -cmd \
  -newsession "$LAB/zap/session-$(date +%Y%m%d-%H%M%S).session" \
  -autorun "$ROOT/parte1/zap/plan.yaml"

echo "[zap] informes:"
ls -lh "$EVIDENCE"/zap-report.*
