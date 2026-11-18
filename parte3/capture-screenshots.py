#!/usr/bin/env python3
"""Captura las pantallas de pfSense usadas en la parte 3 del informe."""

import shutil
import time
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By

BASE = "https://127.0.0.1:8443"
OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"


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


def main() -> None:
    d = driver()
    try:
        pages = [
            ("firewall_rules.php?if=opt1", "07-pfsense-reglas.png"),
            ("status_logs_filter.php", "08-pfsense-firewall-log.png"),
            ("snort/snort_interfaces.php", "09-pfsense-snort-interfaces.png"),
            ("snort/snort_rules.php?id=0", "10-pfsense-snort-regla.png"),
            ("snort/snort_alerts.php?instance=0", "11-pfsense-snort-alertas.png"),
        ]
        for url, name in pages:
            d.get(BASE + "/" + url)
            time.sleep(3)
            d.save_screenshot(str(OUT / name))
            print(name)
        d.get(BASE + "/services_unbound.php")
        time.sleep(2)
        d.find_element(By.ID, "btnadvcustom").click()
        time.sleep(1)
        d.save_screenshot(str(OUT / "12-pfsense-unbound.png"))
        print("12-pfsense-unbound.png")
    finally:
        d.quit()


if __name__ == "__main__":
    main()
