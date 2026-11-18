#!/usr/bin/env python3
"""Configura el laboratorio de la parte 3 desde la GUI de pfSense.

Se ejecuta sobre una instalacion reciente de pfSense 2.7.2 con las cuatro
interfaces ya asignadas (WAN/LAN/OPT1/OPT2). Las funciones comprueban el
estado actual para poder repetir el script sin duplicar reglas.
"""

import shutil
import sys
import time
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

BASE = "https://127.0.0.1:8443"
HERE = Path(__file__).resolve().parent


def driver() -> webdriver.Chrome:
    opts = Options()
    opts.binary_location = shutil.which("chromium")
    for flag in (
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--ignore-certificate-errors",
        "--window-size=1366,1200",
    ):
        opts.add_argument(flag)
    d = webdriver.Chrome(
        service=Service(executable_path=shutil.which("chromedriver")), options=opts
    )
    d.get(BASE + "/")
    time.sleep(1)
    d.find_element(By.NAME, "usernamefld").send_keys("admin")
    d.find_element(By.NAME, "passwordfld").send_keys("pfsense")
    d.find_element(By.NAME, "login").click()
    time.sleep(3)
    return d


def body(d: webdriver.Chrome) -> str:
    return d.find_element(By.TAG_NAME, "body").text


def apply(d: webdriver.Chrome) -> None:
    try:
        d.find_element(By.CSS_SELECTOR, 'button[name="apply"]').click()
    except Exception:
        print("apply: no habia cambios pendientes")
        return
    time.sleep(4)


def add_alias(d: webdriver.Chrome, name: str, desc: str, net: str, bits: int) -> None:
    d.get(BASE + "/firewall_aliases.php")
    time.sleep(1)
    if name in body(d):
        print(f"alias {name}: ya existe")
        return
    d.get(BASE + "/firewall_aliases_edit.php")
    time.sleep(1)
    d.find_element(By.NAME, "name").send_keys(name)
    d.find_element(By.NAME, "descr").send_keys(desc)
    Select(d.find_element(By.NAME, "type")).select_by_visible_text("Network(s)")
    time.sleep(0.3)
    d.find_element(By.NAME, "address0").send_keys(net)
    Select(d.find_element(By.NAME, "address_subnet0")).select_by_value(str(bits))
    d.find_element(By.NAME, "save").click()
    time.sleep(2)
    print(f"alias {name}: creada")


def add_rule(d, action, proto, dsttype, dst, port, descr) -> None:
    d.get(BASE + "/firewall_rules.php?if=opt1")
    time.sleep(1)
    if descr in body(d):
        print(f"regla '{descr}': ya existe")
        return
    d.get(BASE + "/firewall_rules_edit.php?if=opt1")
    time.sleep(1)
    Select(d.find_element(By.NAME, "type")).select_by_value(action)
    Select(d.find_element(By.NAME, "interface")).select_by_value("opt1")
    Select(d.find_element(By.NAME, "ipprotocol")).select_by_value("inet")
    Select(d.find_element(By.NAME, "proto")).select_by_value(proto)
    Select(d.find_element(By.NAME, "dsttype")).select_by_value(dsttype)
    time.sleep(0.3)
    if dst:
        d.find_element(By.NAME, "dst").send_keys(dst)
    if port:
        Select(d.find_element(By.NAME, "dstbeginport")).select_by_value(str(port))
    d.find_element(By.NAME, "log").click()
    d.find_element(By.NAME, "descr").send_keys(descr)
    d.find_element(By.NAME, "save").click()
    time.sleep(2)
    print(f"regla '{descr}': creada")


def setup_snort(d) -> None:
    d.get(BASE + "/snort/snort_interfaces.php")
    time.sleep(2)
    if "OPT1 (vtnet2)" not in body(d):
        d.get(BASE + "/snort/snort_interfaces_edit.php?id=0")
        time.sleep(2)
        Select(d.find_element(By.NAME, "interface")).select_by_value("opt1")
        if not d.find_element(By.NAME, "enable").is_selected():
            d.find_element(By.NAME, "enable").click()
        descr = d.find_element(By.NAME, "descr")
        descr.clear()
        descr.send_keys("OPT1 - VLAN no confiable")
        for name in ("alertsystemlog", "unified2_logging_enable", "blockoffenders7"):
            el = d.find_element(By.NAME, name)
            if not el.is_selected():
                el.click()
        d.find_elements(By.CSS_SELECTOR, 'input[name="save"][value="Save"]')[-1].click()
        time.sleep(4)
        print("Snort: interfaz OPT1 anadida")
    else:
        print("Snort: interfaz OPT1 ya configurada")

    d.get(BASE + "/snort/snort_rules.php?id=0")
    time.sleep(2)
    Select(d.find_element(By.NAME, "selectbox")).select_by_value("custom.rules")
    time.sleep(1)
    rule = (HERE / "snort-custom.rules").read_text()
    ta = d.find_element(By.NAME, "customrules")
    if "sid:1000001" in (ta.get_attribute("value") or ""):
        print("Snort: regla 1000001 ya existia")
    else:
        ta.clear()
        ta.send_keys(rule)
        d.find_element(By.CSS_SELECTOR, "button#save").click()
        time.sleep(3)
        print("Snort: regla 1000001 guardada")

    d.get(BASE + "/snort/snort_interfaces.php")
    time.sleep(2)
    try:
        start = d.find_element(By.ID, "snort_vtnet2_start")
        if "hidden" not in (start.get_attribute("class") or ""):
            start.click()
            time.sleep(8)
            print("Snort: iniciado en OPT1")
        else:
            print("Snort: ya estaba en marcha")
    except Exception:
        print("Snort: no se encontro el control de arranque")


def setup_unbound(d) -> None:
    d.get(BASE + "/services_unbound.php")
    time.sleep(2)
    d.find_element(By.ID, "btnadvcustom").click()
    time.sleep(1)
    text = (HERE / "unbound-phishing.conf").read_text()
    d.execute_script("arguments[0].value=arguments[1]", d.find_element(By.NAME, "custom_options"), text)
    d.find_element(By.CSS_SELECTOR, "button#save").click()
    time.sleep(4)
    apply(d)
    print("Unbound: lista de phishing aplicada")


def main() -> None:
    d = driver()
    try:
        add_alias(d, "VLAN_INTERNA", "VLAN 20 - red interna", "192.168.20.0", 24)
        add_alias(d, "VLAN_NO_CONFIABLE", "VLAN 10 - invitados", "192.168.10.0", 24)
        add_rule(d, "pass", "tcp", "single", "VLAN_INTERNA", 80,
                 "A4-P3: permitir HTTP al servidor interno")
        add_rule(d, "pass", "tcp/udp", "(self)", None, 53,
                 "A4-P3: permitir DNS al resolver para filtrado de contenido")
        add_rule(d, "block", "any", "single", "VLAN_INTERNA", None,
                 "A4-P3: bloquear trafico no autorizado a VLAN interna")
        d.get(BASE + "/firewall_rules.php?if=opt1")
        time.sleep(2)
        apply(d)
        setup_snort(d)
        setup_unbound(d)
    finally:
        d.quit()


if __name__ == "__main__":
    sys.exit(main())
