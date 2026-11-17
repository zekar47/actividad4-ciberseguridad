#!/usr/bin/env python3
"""Inicializa DVWA y deja una sesión autenticada en .lab/dvwa-session.env.

No usa dependencias externas: solo la biblioteca estándar. El flujo es el mismo
que seguiría una persona en el navegador:
  1. /setup.php            -> crear/reiniciar la base de datos
  2. /login.php            -> autenticarse (admin/password)
  3. /security.php         -> fijar el nivel de seguridad en "low"
  4. módulo SQLi            -> comprobar que la sesión es válida
"""

from __future__ import annotations

import http.cookiejar
import os
import re
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("DVWA_URL", "http://127.0.0.1:8081").rstrip("/")
OUT = os.environ.get("DVWA_SESSION_FILE", ".lab/dvwa-session.env")


def token(html: str) -> str:
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", html)
    if not m:
        m = re.search(r"value=['\"]([^'\"]+)['\"]\s+name=['\"]user_token['\"]", html)
    if not m:
        raise RuntimeError("no se encontró user_token en la página")
    return m.group(1)


def main() -> int:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler(),
    )

    def get(path: str) -> str:
        with opener.open(BASE + path, timeout=20) as r:
            return r.read().decode("utf-8", "replace")

    def post(path: str, data: dict[str, str]) -> str:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(BASE + path, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with opener.open(req, timeout=30) as r:
            return r.read().decode("utf-8", "replace")

    # 1. Base de datos
    setup = get("/setup.php")
    post("/setup.php", {"create_db": "Create / Reset Database", "user_token": token(setup)})

    # 2. Login
    login = get("/login.php")
    post(
        "/login.php",
        {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token(login),
        },
    )

    # 3. Nivel bajo (necesario para reproducir los fallos didácticos de DVWA)
    security = get("/security.php")
    post(
        "/security.php",
        {"security": "low", "seclev_submit": "Submit", "user_token": token(security)},
    )

    # 4. Verificación funcional
    sqli = get("/vulnerabilities/sqli/?id=1&Submit=Submit")
    if "First name" not in sqli:
        print("ERROR: la sesión no llegó al módulo SQLi", file=sys.stderr)
        return 1

    cookies = {c.name: c.value for c in jar}
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("# Sesión DVWA generada automáticamente; no versionar.\n")
        fh.write(f"DVWA_COOKIE=PHPSESSID={cookies.get('PHPSESSID', '')}; security={cookies.get('security', 'low')}\n")
    print(f"DVWA lista en {BASE} (seguridad={cookies.get('security', 'low')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
