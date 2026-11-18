#!/usr/bin/env python3
"""Genera las capturas de pantalla que acompañan al informe.

Requiere el laboratorio de la parte 1 levantado (`parte1/scripts/lab-up.sh`) y
el binario de la parte 2 compilado (`make -C parte2`). Se ejecuta con el
entorno auxiliar del flake:

    nix develop .#screenshots -c python3 scripts/capture-screenshots.py

Las capturas se guardan en `docs/screenshots/`. Son artefactos reales: las
tres primeras son vistas del navegador sobre DVWA, la cuarta es el informe de
ZAP y las dos últimas son la salida real de las pruebas y del flujo de la API.
"""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select, WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException
from PIL import Image, ImageChops

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
BASE = os.environ.get("DVWA_URL", "http://127.0.0.1:8081").rstrip("/")
TMP = Path("/tmp/opencode")

USER = "admin"
PASSWORD = "password"

SQLI_PAYLOAD = "1' UNION SELECT user, password FROM users -- -"
XSS_PAYLOAD = (
    "</pre><p style=\"color:#b00020;font:600 18px/1.6 sans-serif;"
    "word-break:break-all;margin:8px 0\">"
    "XSS ejecutado &#8212; cookie: <span id=\"poc\"></span></p>"
    "<script>document.getElementById('poc').textContent = document.cookie;</script>"
    "<pre>"
)


def http_ok(url: str, timeout: float = 3) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout):
            return True
    except OSError:
        return False


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_driver(width: int = 1366, height: int = 900) -> webdriver.Chrome:
    opts = Options()
    opts.binary_location = shutil.which("chromium")
    for arg in (
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        f"--window-size={width},{height}",
    ):
        opts.add_argument(arg)
    service = Service(executable_path=shutil.which("chromedriver"))
    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(30)
    return driver


def wait_text(driver, needle: str, timeout: int = 15) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if needle in driver.find_element(By.TAG_NAME, "body").text:
                return
        except StaleElementReferenceException:
            # La página se está recargando; se reintenta con el DOM nuevo.
            pass
        time.sleep(0.2)
    raise TimeoutException(f"no apareció el texto: {needle!r}")


def shot(driver, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    driver.save_screenshot(str(path))
    print(f"[captura] {path.relative_to(ROOT)}")


def shot_element(driver, selector: str, path: Path) -> None:
    el = driver.find_element(By.CSS_SELECTOR, selector)
    driver.execute_script(
        "arguments[0].scrollIntoView({block: 'start', inline: 'nearest'});", el
    )
    time.sleep(0.3)
    path.parent.mkdir(parents=True, exist_ok=True)
    el.screenshot(str(path))
    print(f"[captura] {path.relative_to(ROOT)}")


def trim_white(path: Path, pad: int = 20) -> None:
    """Recorta el margen blanco sobrante (solo presentación)."""
    im = Image.open(path).convert("RGB")
    bg = Image.new("RGB", im.size, (255, 255, 255))
    bbox = ImageChops.difference(im, bg).getbbox()
    if not bbox:
        return
    box = (
        max(0, bbox[0] - pad),
        max(0, bbox[1] - pad),
        min(im.width, bbox[2] + pad),
        min(im.height, bbox[3] + pad),
    )
    im.crop(box).save(path)


def login(driver) -> None:
    driver.get(f"{BASE}/login.php")
    driver.find_element(By.NAME, "username").send_keys(USER)
    driver.find_element(By.NAME, "password").send_keys(PASSWORD)
    driver.find_element(By.NAME, "Login").click()
    WebDriverWait(driver, 15).until(
        lambda d: "login.php" not in d.current_url and "index.php" in d.current_url
    )

    # Nivel bajo: reproduce los fallos didácticos de DVWA.
    driver.get(f"{BASE}/security.php")
    Select(driver.find_element(By.NAME, "security")).select_by_value("low")
    driver.find_element(By.NAME, "seclev_submit").click()
    wait_text(driver, "Security level set to low")


def capture_dvwa(driver) -> None:
    login(driver)

    # 1. SQL Injection: la respuesta incluye los hashes de todos los usuarios.
    query = urllib.parse.urlencode({"id": SQLI_PAYLOAD, "Submit": "Submit"})
    driver.get(f"{BASE}/vulnerabilities/sqli/?{query}")
    wait_text(driver, "First name:")
    shot_element(driver, "#container", OUT / "01-sqli.png")

    # 2. XSS reflejado: el payload se ejecuta y escribe la cookie en el DOM.
    query = urllib.parse.urlencode({"name": XSS_PAYLOAD})
    driver.get(f"{BASE}/vulnerabilities/xss_r/?{query}")
    WebDriverWait(driver, 10).until(
        EC.text_to_be_present_in_element((By.ID, "poc"), "PHPSESSID")
    )
    shot_element(driver, "#container", OUT / "02-xss.png")

    # 3. Broken Access Control: JSON completo sin enviar cookie de sesión.
    anon = start_driver(1366, 300)
    try:
        anon.get(f"{BASE}/vulnerabilities/authbypass/get_user_data.php")
        WebDriverWait(anon, 10).until(
            EC.text_to_be_present_in_element(
                (By.TAG_NAME, "body"), '"first_name"'
            )
        )
        # Solo presentación: la línea JSON es muy larga y se sale de la vista.
        anon.execute_script(
            """
            document.body.style.whiteSpace = 'pre-wrap';
            document.body.style.wordBreak = 'break-word';
            document.body.style.font = '16px/1.6 monospace';
            document.body.style.padding = '20px';
            """
        )
        time.sleep(0.8)
        anon.save_screenshot(str(OUT / "03-authbypass.png"))
        trim_white(OUT / "03-authbypass.png")
        print(f"[captura] {(OUT / '03-authbypass.png').relative_to(ROOT)}")
    finally:
        anon.quit()


def capture_zap() -> None:
    report = ROOT / "parte1" / "evidence" / "zap-report.html"
    if not report.exists():
        raise SystemExit(
            "falta parte1/evidence/zap-report.html; ejecuta parte1/scripts/run-zap.sh"
        )
    driver = start_driver(1440, 1020)
    try:
        driver.get(report.as_uri())
        wait_text(driver, "Summary of Alerts", timeout=20)
        time.sleep(0.5)
        shot(driver, OUT / "04-zap.png")
    finally:
        driver.quit()


TERMINAL_CSS = """
  * { box-sizing: border-box; }
  body { margin: 0; background: #11111b; }
  #term {
    width: 900px;
    margin: 0;
    background: #1e1e2e;
    font-family: "DejaVu Sans Mono", "Liberation Mono", monospace;
  }
  .bar {
    background: #313244;
    color: #cdd6f4;
    font: 14px "DejaVu Sans", sans-serif;
    padding: 9px 14px;
    letter-spacing: .02em;
  }
  .dot { display: inline-block; width: 11px; height: 11px; border-radius: 50%;
         margin-right: 7px; vertical-align: -1px; }
  .r { background: #f38ba8; } .y { background: #f9e2af; } .g { background: #a6e3a1; }
  pre {
    margin: 0;
    padding: 20px 24px 24px;
    color: #cdd6f4;
    font-size: 16px;
    line-height: 1.3;
    white-space: pre-wrap;
    overflow-wrap: break-word;
  }
  .p { color: #89b4fa; font-weight: 600; }
  .ok { color: #a6e3a1; }
  .err { color: #f38ba8; }
  .dim { color: #9399b2; }
"""


def terminal_screenshot(title: str, text: str, path: Path) -> None:
    body = html.escape(text)
    body = re.sub(
        r"(?m)^(\$ .*)$", r'<span class="p">\1</span>', body
    )
    body = re.sub(
        r"(?m)^(HTTP/1\.1 [45]\d\d.*|HTTP [45]\d\d.*)$",
        r'<span class="err">\1</span>',
        body,
    )
    body = re.sub(
        r"(?m)^(HTTP/1\.1 2\d\d.*|HTTP 2\d\d.*)$", r'<span class="ok">\1</span>', body
    )
    body = re.sub(r"(?m)^(# .*)$", r'<span class="dim">\1</span>', body)
    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<style>{TERMINAL_CSS}</style></head><body>"
        '<div id="term">'
        f'<div class="bar"><span class="dot r"></span><span class="dot y"></span>'
        f'<span class="dot g"></span>{html.escape(title)}</div>'
        f"<pre>{body}</pre></div></body></html>"
    )
    TMP.mkdir(parents=True, exist_ok=True)
    page = TMP / (path.stem + ".html")
    page.write_text(doc, encoding="utf-8")

    driver = start_driver(960, 2400)
    try:
        driver.get(page.as_uri())
        driver.execute_script("return document.fonts.ready")
        time.sleep(0.4)
        shot_element(driver, "#term", path)
    finally:
        driver.quit()


def curl(cmd: str, env: dict[str, str]) -> str:
    p = subprocess.run(
        ["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=30
    )
    if p.returncode != 0:
        raise RuntimeError(f"curl falló: {cmd}\n{p.stderr}")
    return p.stdout.strip()


def start_api(port: int, limit: int = 100) -> subprocess.Popen:
    binary = ROOT / "parte2" / "api"
    if not binary.exists():
        raise SystemExit("falta parte2/api; ejecuta: nix develop -c make -C parte2")
    env = os.environ.copy()
    env.update(
        {
            "A4_PORT": str(port),
            "A4_JWT_SECRET": "capturas-jwt-secret-0123456789abcdef",
            "A4_CLIENT_SECRET": "capturas-client-secret",
            "A4_RATE_LIMIT": str(limit),
            "A4_RATE_WINDOW": "60",
        }
    )
    proc = subprocess.Popen(
        [str(binary)], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        if http_ok(f"http://127.0.0.1:{port}/healthz", timeout=0.5):
            return proc
        time.sleep(0.05)
    proc.kill()
    raise RuntimeError("la API no arrancó")


def api_flow_text() -> str:
    """Transcripción real del flujo de la API (comandos y salidas)."""
    env = os.environ.copy()
    env["CLIENT_SECRET"] = "capturas-client-secret"

    def run(cmd: str, base: str, extra: dict[str, str] | None = None) -> str:
        return curl(
            cmd.replace("__BASE__", base),
            {**env, "BASE": base, **(extra or {})},
        )

    token_cmd = (
        "curl -s -X POST $BASE/oauth/token "
        "-d 'grant_type=client_credentials&client_id=demo-client' "
        "-d \"client_secret=$CLIENT_SECRET&scope=read transfer\" "
        "| jq -r .access_token"
    )

    port = free_port()
    proc = start_api(port)
    base = f"http://127.0.0.1:{port}"
    lines: list[str] = [
        "# Parte 2 - flujo OAuth 2.0 / JWT / validacion de entradas",
        "",
        f"$ BASE={base}",
        "$ CLIENT_SECRET=capturas-client-secret",
        "$ TOKEN=$(%s)" % token_cmd,
        "",
        '$ curl -s $BASE/api/v1/profile -H "Authorization: Bearer $TOKEN" | jq',
    ]
    try:
        token = run(token_cmd, base)
        profile = run(
            'curl -s $BASE/api/v1/profile -H "Authorization: Bearer $TOKEN" | jq',
            base, {"TOKEN": token},
        )
        lines.append(profile)

        transfer_cmd = (
            "curl -s -X POST $BASE/api/v1/transfers "
            '-H "Authorization: Bearer $TOKEN" '
            "-H 'Content-Type: application/json' "
            "-d '{\"account\":\"ABC-1234\",\"amount\":250}' | jq"
        )
        lines += ["", "$ " + transfer_cmd]
        lines.append(run(transfer_cmd, base, {"TOKEN": token}))

        sqli_cmd = (
            "curl -s -X POST $BASE/api/v1/transfers "
            '-H "Authorization: Bearer $TOKEN" '
            "-H 'Content-Type: application/json' "
            "-d \"{\\\"account\\\":\\\"ABC-1234' OR '1'='1\\\","
            "\\\"amount\\\":250}\" "
            "-w '\\nHTTP %{http_code}\\n'"
        )
        lines += [
            "",
            "# inyeccion SQL en 'account': se rechaza en la frontera",
            "$ " + sqli_cmd,
        ]
        lines.append(run(sqli_cmd, base, {"TOKEN": token}))

        lines += [
            "",
            '$ curl -s -o /dev/null -w \'HTTP %{http_code}\\n\' '
            "$BASE/api/v1/profile",
        ]
        lines.append(
            run(
                "curl -s -o /dev/null -w 'HTTP %{http_code}\\n' "
                "$BASE/api/v1/profile",
                base,
            )
        )
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # Segundo proceso con límite reducido para que el 429 sea reproducible.
    port = free_port()
    proc = start_api(port, limit=3)
    base = f"http://127.0.0.1:{port}"
    try:
        token = run(token_cmd.replace("read transfer", "read"), base)
        loop_cmd = (
            "for i in 1 2 3 4; do curl -s -o /dev/null -w '%{http_code} ' "
            '-H "Authorization: Bearer $TOKEN" $BASE/api/v1/profile; done'
        )
        codes = run(loop_cmd, base, {"TOKEN": token})
        retry = run(
            'curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" '
            "$BASE/api/v1/profile | grep -i '^retry-after'",
            base, {"TOKEN": token},
        )
        lines += [
            "",
            "# limite reducido para la demostracion: A4_RATE_LIMIT=3 "
            "(por defecto 100/min)",
            f"$ BASE={base}",
            "$ TOKEN=$(%s)" % token_cmd.replace("read transfer", "read"),
            "$ " + loop_cmd,
            codes,
            '$ curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" '
            "$BASE/api/v1/profile | grep -i '^retry-after'",
            retry,
        ]
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    return "\n".join(lines) + "\n"


def capture_part2() -> None:
    results = ROOT / "parte2" / "evidence" / "test-results.txt"
    if not results.exists():
        raise SystemExit(
            "falta parte2/evidence/test-results.txt; ejecuta: "
            "nix develop -c make -C parte2 test"
        )
    text = (
        "$ nix develop .. -c make test\n\n"
        + results.read_text(encoding="utf-8").strip()
        + "\n"
    )
    terminal_screenshot(
        "parte2 - flujo OAuth 2.0, JWT y validacion",
        api_flow_text(), OUT / "05-flujo-api.png",
    )
    terminal_screenshot(
        "parte2 - pruebas automatizadas (make test)",
        text, OUT / "06-pruebas-api.png",
    )


def main() -> int:
    if not http_ok(f"{BASE}/login.php"):
        print(
            "el laboratorio no responde en %s; ejecuta primero "
            "parte1/scripts/lab-up.sh" % BASE,
            file=sys.stderr,
        )
        return 2

    OUT.mkdir(parents=True, exist_ok=True)

    driver = start_driver()
    try:
        capture_dvwa(driver)
    finally:
        driver.quit()

    capture_zap()
    capture_part2()

    print(f"\nCapturas en {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
