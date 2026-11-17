#!/usr/bin/env python3
"""Pruebas de aceptación de a4-api (solo biblioteca estándar).

Cubre:
  - OAuth 2.0 client credentials;
  - JWT HS256 (firma, alg, exp, iss, aud, scope);
  - validación de entradas (SQLi/XSS/command injection/traversal);
  - rate limiting 100/min, 429 + Retry-After y reinicio de ventana;
  - cabeceras y códigos de error.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "api"
EVIDENCE = ROOT / "evidence"
JWT_SECRET = "test-jwt-secret-0123456789abcdef"
CLIENT_SECRET = "test-client-secret"
CLIENT_ID = "demo-client"
ISSUER = "https://auth.a4.local"
AUDIENCE = "a4-api"

results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail and not cond else ""))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def request(port: int, method: str, path: str, body: str | None = None,
            headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    try:
        data = r.read().decode("utf-8", "replace")
    except ConnectionResetError:
        data = ""
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, hdrs, data


class Server:
    def __init__(self, *, limit: int = 100, window: int = 60):
        self.port = free_port()
        self.log = EVIDENCE / f"server-{self.port}.log"
        env = os.environ.copy()
        env.update({
            "A4_PORT": str(self.port),
            "A4_JWT_SECRET": JWT_SECRET,
            "A4_CLIENT_SECRET": CLIENT_SECRET,
            "A4_RATE_LIMIT": str(limit),
            "A4_RATE_WINDOW": str(window),
        })
        self.proc = subprocess.Popen(
            [str(BIN)], env=env, stdout=self.log.open("wb"),
            stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            try:
                s, _, _ = request(self.port, "GET", "/healthz")
                if s == 200:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise RuntimeError("el servidor no arrancó")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(claims: dict, secret: str = JWT_SECRET,
             header: dict | None = None) -> str:
    h = b64url(json.dumps(header or {"alg": "HS256", "typ": "JWT"},
                          separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64url(hmac.new(secret.encode(), f"{h}.{p}".encode(),
                          hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def claims(scope: str = "read", **over) -> dict:
    now = int(time.time())
    c = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": CLIENT_ID,
        "scope": scope,
        "iat": now,
        "exp": now + 900,
        "jti": "test-jti",
    }
    c.update(over)
    return c


def token(port: int, scope: str = "read", secret: str = CLIENT_SECRET) -> str:
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": secret,
        "scope": scope,
    })
    s, _, b = request(port, "POST", "/oauth/token", body,
                      {"Content-Type": "application/x-www-form-urlencoded"})
    assert s == 200, (s, b)
    return json.loads(b)["access_token"]


def auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def main() -> int:
    EVIDENCE.mkdir(exist_ok=True)
    if not BIN.exists():
        print("falta el binario; ejecuta: make", file=sys.stderr)
        return 2

    # ---------------------------------------------------------------- OAuth
    srv = Server()
    try:
        s, h, b = request(srv.port, "GET", "/healthz")
        check("healthz responde 200", s == 200 and "ok" in b, f"{s} {b}")

        s, h, b = request(srv.port, "POST", "/oauth/token",
                          "grant_type=client_credentials",
                          {"Content-Type": "application/x-www-form-urlencoded"})
        check("token sin credenciales -> 400", s == 400, f"{s} {b}")

        s, h, b = request(srv.port, "POST", "/oauth/token",
                          urllib.parse.urlencode({
                              "grant_type": "client_credentials",
                              "client_id": CLIENT_ID,
                              "client_secret": "incorrecto",
                          }),
                          {"Content-Type": "application/x-www-form-urlencoded"})
        check("token con secreto incorrecto -> 401", s == 401, f"{s} {b}")

        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "admin",
        })
        s, h, b = request(srv.port, "POST", "/oauth/token", body,
                          {"Content-Type": "application/x-www-form-urlencoded"})
        check("scope no permitido -> 400", s == 400 and "invalid_scope" in b,
              f"{s} {b}")

        body = urllib.parse.urlencode({
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        })
        s, h, b = request(srv.port, "POST", "/oauth/token", body,
                          {"Content-Type": "application/x-www-form-urlencoded"})
        check("grant_type no soportado -> 400", s == 400, f"{s} {b}")

        tok = token(srv.port, "read transfer")
        s, h, b = request(srv.port, "GET", "/api/v1/profile", headers=auth(tok))
        check("token válido accede a /profile", s == 200 and CLIENT_ID in b,
              f"{s} {b}")
        check("respuesta no se cachea",
              h.get("cache-control") == "no-store", str(h))

        s, h, b = request(srv.port, "GET", "/api/v1/profile",
                          headers={"Authorization": "Bearer " + tok + "x"})
        check("token manipulado -> 401", s == 401, f"{s} {b}")

        s, h, b = request(srv.port, "GET", "/api/v1/profile")
        check("sin token -> 401 + WWW-Authenticate",
              s == 401 and "www-authenticate" in h, f"{s} {h}")

        s, h, b = request(srv.port, "GET", "/api/v1/profile",
                          headers={"Authorization": "Basic abc"})
        check("esquema distinto de Bearer -> 401", s == 401, f"{s} {b}")

        none_tok = make_jwt(claims(), header={"alg": "none", "typ": "JWT"})
        none_tok = none_tok.rsplit(".", 1)[0] + "."
        s, _, b = request(srv.port, "GET", "/api/v1/profile",
                          headers=auth(none_tok))
        check("JWT alg=none -> 401", s == 401, f"{s} {b}")

        wrong_secret = make_jwt(claims(), secret="otro-secreto")
        s, _, b = request(srv.port, "GET", "/api/v1/profile",
                          headers=auth(wrong_secret))
        check("JWT firmado con otro secreto -> 401", s == 401, f"{s} {b}")

        expired = make_jwt(claims(exp=int(time.time()) - 1,
                                  iat=int(time.time()) - 901))
        s, _, b = request(srv.port, "GET", "/api/v1/profile",
                          headers=auth(expired))
        check("JWT expirado -> 401", s == 401, f"{s} {b}")

        wrong_aud = make_jwt(claims(aud="otra-api"))
        s, _, b = request(srv.port, "GET", "/api/v1/profile",
                          headers=auth(wrong_aud))
        check("JWT con audiencia incorrecta -> 401", s == 401, f"{s} {b}")

        wrong_iss = make_jwt(claims(iss="https://evil.local"))
        s, _, b = request(srv.port, "GET", "/api/v1/profile",
                          headers=auth(wrong_iss))
        check("JWT con emisor incorrecto -> 401", s == 401, f"{s} {b}")

        read_tok = token(srv.port, "read")
        s, _, b = request(srv.port, "POST", "/api/v1/transfers",
                          json.dumps({"account": "ABC-1234", "amount": 10}),
                          {**auth(read_tok), "Content-Type": "application/json"})
        check("scope read no puede transferir -> 403", s == 403, f"{s} {b}")

        transfer_tok = token(srv.port, "read transfer")
        s, h, b = request(srv.port, "POST", "/api/v1/transfers",
                          json.dumps({"account": "ABC-1234", "amount": 250}),
                          {**auth(transfer_tok),
                           "Content-Type": "application/json; charset=utf-8"})
        check("transferencia válida -> 200", s == 200 and "accepted" in b,
              f"{s} {b}")

        # ------------------------------------------------ validación de entradas
        bad_accounts = [
            "abc-1234", "ABCD-1234", "ABC-123", "ABC-12345", "ABC_1234",
            "ABC-1234' OR '1'='1", "ABC-1234; id", "../../etc/passwd",
            "<script>alert(1)</script>", "ABC-1234\n", "ABC-1234 ",
        ]
        for acct in bad_accounts:
            s, _, b = request(srv.port, "POST", "/api/v1/transfers",
                              json.dumps({"account": acct, "amount": 1}),
                              {**auth(transfer_tok),
                               "Content-Type": "application/json"})
            check(f"cuenta inválida rechazada: {acct!r}", s == 400,
                  f"{s} {b}")

        bad_amounts = [0, -5, 1000001, "100", 1.5, True, None]
        for amt in bad_amounts:
            s, _, b = request(srv.port, "POST", "/api/v1/transfers",
                              json.dumps({"account": "ABC-1234", "amount": amt}),
                              {**auth(transfer_tok),
                               "Content-Type": "application/json"})
            check(f"monto inválido rechazado: {amt!r}", s == 400, f"{s} {b}")

        bad_json = [
            '{"account":"ABC-1234","amount":1,"role":"admin"}',
            '{"account":"ABC-1234","account":"ABC-1234","amount":1}',
            '{"account":"ABC-1234"}',
            '{"account":"ABC-1234","amount":1',
            '{"account":"ABC-1234","amount":1} basura',
            '{"account":"ABC-1234","amount":01}',
            '{"account":"ABC-1234","amount":1e3}',
        ]
        for payload in bad_json:
            s, _, b = request(srv.port, "POST", "/api/v1/transfers", payload,
                              {**auth(transfer_tok),
                               "Content-Type": "application/json"})
            check(f"JSON inválido rechazado: {payload[:38]!r}", s == 400,
                  f"{s} {b}")

        s, _, b = request(srv.port, "POST", "/api/v1/transfers",
                          '{"account":"ABC-1234","amount":1}',
                          {**auth(transfer_tok), "Content-Type": "text/plain"})
        check("content-type incorrecto -> 415", s == 415, f"{s} {b}")

        s, _, b = request(srv.port, "POST", "/api/v1/transfers", "a" * 2000,
                          {**auth(transfer_tok),
                           "Content-Type": "application/json"})
        check("cuerpo demasiado grande -> 413", s == 413, f"{s} {b}")

        s, _, b = request(srv.port, "GET", "/no-existe")
        check("ruta inexistente -> 404", s == 404, f"{s} {b}")
    finally:
        srv.stop()

    # ------------------------------------------------------- rate limiting
    srv = Server(limit=100, window=60)
    try:
        tok = token(srv.port, "read")
        statuses = []
        for _ in range(100):
            s, _, _ = request(srv.port, "GET", "/api/v1/profile",
                              headers=auth(tok))
            statuses.append(s)
        s, h, b = request(srv.port, "GET", "/api/v1/profile",
                          headers=auth(tok))
        check("100 solicitudes/min permitidas", all(x == 200 for x in statuses),
              f"no-200={[x for x in statuses if x != 200][:5]}")
        check("solicitud 101 -> 429", s == 429, f"{s} {b}")
        check("429 incluye Retry-After válido",
              h.get("retry-after", "").isdigit() and
              1 <= int(h.get("retry-after", "0")) <= 60,
              str(h.get("retry-after")))
    finally:
        srv.stop()

    srv = Server(limit=2, window=2)
    try:
        tok = token(srv.port, "read")
        s1, _, _ = request(srv.port, "GET", "/api/v1/profile",
                           headers=auth(tok))
        s2, _, _ = request(srv.port, "GET", "/api/v1/profile",
                           headers=auth(tok))
        s3, _, _ = request(srv.port, "GET", "/api/v1/profile",
                           headers=auth(tok))
        check("ventana de 2 solicitudes se agota",
              (s1, s2, s3) == (200, 200, 429), f"{s1},{s2},{s3}")
        time.sleep(2.1)
        s4, _, _ = request(srv.port, "GET", "/api/v1/profile",
                           headers=auth(tok))
        check("la ventana se reinicia", s4 == 200, f"{s4}")

        # El endpoint de token tiene su propio cubo por IP; la espera anterior
        # también reinició su ventana.
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "read",
        })
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        t1, _, _ = request(srv.port, "POST", "/oauth/token", body, hdrs)
        t2, _, _ = request(srv.port, "POST", "/oauth/token", body, hdrs)
        t3, h3, _ = request(srv.port, "POST", "/oauth/token", body, hdrs)
        check("rate limit también protege /oauth/token",
              (t1, t2, t3) == (200, 200, 429) and
              "retry-after" in h3, f"{t1},{t2},{t3}")
    finally:
        srv.stop()

    # ------------------------------------------------------------- resumen
    failed = [r for r in results if not r[1]]
    out = EVIDENCE / "test-results.txt"
    with out.open("w", encoding="utf-8") as fh:
        fh.write("Pruebas de a4-api\n")
        fh.write(f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"Resultado: {len(results) - len(failed)}/{len(results)} "
                 "correctas\n\n")
        for name, ok, detail in results:
            fh.write(f"{'PASS' if ok else 'FAIL'}  {name}")
            if detail and not ok:
                fh.write(f"  [{detail}]")
            fh.write("\n")
    print(f"\n{len(results) - len(failed)}/{len(results)} pruebas correctas")
    print(f"evidencia: {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
