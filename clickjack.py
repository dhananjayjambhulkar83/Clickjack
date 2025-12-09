#!/usr/bin/env python3
"""
clickjack.py – Complete Clickjacking Scanner

Features:
- Chrome + Selenium (headless by default)
- Auto SSL fallback (verify=False)
- Timeout / SSL / Unreachable labels
- If iframe loads → [VULNERABLE]
- Saves PoC HTML for vulnerable targets (./poc_html/)
- Optional: save output to TXT (--save-txt)
"""

from __future__ import annotations
import argparse
import os
import re
import time
import urllib3
from typing import Dict, List, Optional

import certifi
import requests
from requests.exceptions import (
    RequestException, SSLError, ConnectTimeout,
    ConnectionError
)

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By

from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager

from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "clickjack-externalhtml/1.0"
LOCAL_POC_NAME = "clickjacking.html"
POC_OUTPUT_DIR = "poc_html"
LOG_FILE: Optional[str] = None


# ================= LOGGING =================
def log(text: str):
    print(text)
    global LOG_FILE
    if LOG_FILE:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")


# ================= HELPERS =================
def ensure_scheme_try_both(t: str) -> List[str]:
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", t):
        return [t]
    return [f"https://{t}", f"http://{t}"]


def parse_xfo(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    v = val.strip().upper()
    if "DENY" in v:
        return "DENY"
    if "SAMEORIGIN" in v:
        return "SAMEORIGIN"
    if "ALLOW-FROM" in v:
        return "ALLOW-FROM"
    return v


def headers_block_framing(headers: Dict[str, str]):
    xfo = headers.get("X-Frame-Options") or headers.get("x-frame-options")
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")

    if xfo:
        px = parse_xfo(xfo)
        if px in ("DENY", "SAMEORIGIN", "ALLOW-FROM"):
            return True, f"Header blocks framing: X-Frame-Options={xfo}"

    if csp and "frame-ancestors" in csp.lower():
        return True, "Header blocks framing: CSP frame-ancestors exists"

    return False, "No blocking headers"


# ================= BROWSER =================
def start_browser(visible: bool):
    opts = ChromeOptions()
    if not visible:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument(f"--user-agent={USER_AGENT}")

    chrome_path = ChromeDriverManager().install()
    service = ChromeService(chrome_path)
    return webdriver.Chrome(service=service, options=opts)


# ============== POC TEMPLATE ===============
def load_poc_template() -> str:
    if not os.path.exists(LOCAL_POC_NAME):
        raise FileNotFoundError(f"{LOCAL_POC_NAME} not found!")
    with open(LOCAL_POC_NAME, "r", encoding="utf-8") as f:
        return f.read()


def generate_poc_html(template: str, target: str) -> str:
    pattern = re.compile(r'(<iframe\b[^>]*\bsrc\s*=\s*")[^"]*(")', re.IGNORECASE)
    if pattern.search(template):
        return pattern.sub(r"\1" + target + r"\2", template, count=1)

    iframe = (
        f'\n<iframe id="cjframe" src="{target}" width="1000" height="700" '
        f'style="border:3px solid #333;"></iframe>\n'
    )

    if "</body>" in template.lower():
        return re.sub(r"</body>", iframe + "</body>", template, flags=re.IGNORECASE)

    return template + iframe


def write_temp_poc(html: str) -> str:
    path = "_clickjack_tmp.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def save_vuln_poc(target: str, html: str) -> str:
    os.makedirs(POC_OUTPUT_DIR, exist_ok=True)
    parsed = urlparse(target)

    parts = [
        parsed.scheme or "",
        parsed.netloc or "",
        parsed.path.strip("/").replace("/", "_") if parsed.path not in ["", "/"] else ""
    ]

    base = "_".join([x for x in parts if x])
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    filename = f"{base}.html"

    out = os.path.join(POC_OUTPUT_DIR, filename)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    return out


# ============== FRAME CHECK ================
def iframe_render_check(poc_path: str, headless: bool, timeout: int, retries: int):
    last = None
    for _ in range(retries + 1):
        driver = None
        try:
            driver = start_browser(visible=not headless)
            driver.set_page_load_timeout(max(30, timeout * 2))

            driver.get(f"file://{os.path.abspath(poc_path)}")
            time.sleep(1)

            try:
                iframe = driver.find_element(By.ID, "cjframe")
            except Exception:
                try:
                    iframe = driver.find_element(By.TAG_NAME, "iframe")
                except Exception:
                    driver.quit()
                    return False, "No iframe found"

            try:
                try:
                    driver.switch_to.frame("cjframe")
                except Exception:
                    driver.switch_to.frame(iframe)

                try:
                    driver.find_element(By.TAG_NAME, "body")
                except Exception:
                    pass

                driver.quit()
                return True, "Iframe loaded → framable"

            except WebDriverException:
                driver.quit()
                return False, "Frame blocked"

        except Exception as e:
            last = e
            if driver:
                driver.quit()
            time.sleep(1)

    return False, f"Browser error: {last}"


# ============= MAIN URL CHECK =============
def check_one(target: str, timeout: int, retries: int, no_verify: bool, headless: bool, only_vuln: bool):
    target = target.strip()
    if not target:
        return

    used = None
    headers = {}
    last_err = None

    for url in ensure_scheme_try_both(target):
        attempt = 0
        while attempt <= retries:
            try:
                verify_arg = False if no_verify else certifi.where()
                resp = requests.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=timeout,
                    verify=verify_arg,
                )
                used = url
                headers = resp.headers
                break

            except SSLError as s:
                last_err = s
                try:
                    resp = requests.get(
                        url,
                        headers={"User-Agent": USER_AGENT},
                        timeout=timeout,
                        verify=False,
                    )
                    used = url
                    headers = resp.headers
                    break
                except Exception as e2:
                    last_err = e2
                    attempt += 1
                    continue

            except (ConnectTimeout, ConnectionError, RequestException) as e:
                last_err = e
                attempt += 1
                continue

        if used:
            break

    if not used:
        if not only_vuln:
            m = (str(last_err) or "").lower()
            if "timeout" in m:
                log(f"[TIMEOUT] {target} – Site not responding")
            elif "ssl" in m or "certificate" in m:
                log(f"[SSL ERROR] {target} – SSL validation failed")
            elif "connection" in m:
                log(f"[UNREACHABLE] {target} – Host unreachable")
            else:
                log(f"[ERROR] {target} – {last_err}")
        return

    blocked, reason = headers_block_framing(headers)
    if blocked:
        if not only_vuln:
            log(f"[NOT VULNERABLE] {used} – {reason}")
        return

    try:
        template = load_poc_template()
    except Exception as e:
        log(f"[ERROR] {used} – PoC template issue: {e}")
        return

    html = generate_poc_html(template, used)
    temp = write_temp_poc(html)

    vuln, msg = iframe_render_check(temp, headless, timeout, retries)

    if vuln:
        out = save_vuln_poc(used, html)
        log(f"[VULNERABLE] {used} – PoC saved: {out}")
    else:
        if not only_vuln:
            log(f"[NOT VULNERABLE] {used} – {msg}")


# ================== MAIN ===================
def main():
    global LOG_FILE
    import sys

    # Custom handling for -h / --help BEFORE argparse runs
    if any(h in sys.argv[1:] for h in ("-h", "--help")):
        print("==============================================")
        print("  CLICKJACKING SCANNER – HELP & OPTIONS")
        print("==============================================")
        print("Required:")
        print("  -u URL              Test a single URL")
        print("  -f FILE             Test URLs from a file")
        print("")
        print("Useful Flags:")
        print("  --save-txt FILE     Save output to a log file")
        print("  --only-vuln         Show only vulnerable URLs")
        print("  --verbose           Show real browser window")
        print("  --timeout N         Set timeout (default 10)")
        print("  --retries N         Retry count (default 2)")
        print("  --no-verify         Disable SSL checks")
        print("")
        print("Auto Features:")
        print("  ✔ SSL fallback on error")
        print("  ✔ Timeout / unreachable / SSL error labels")
        print("  ✔ PoC saved for vulnerable sites → ./poc_html/")
        print("==============================================")
        print("")
        print("Usage:")
        print("  python clickjack.py -u URL [options]")
        print("  python clickjack.py -f FILE [options]")
        print("")
        return

    parser = argparse.ArgumentParser(description="Clickjacking Scanner (Chrome-based)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Test a single URL")
    group.add_argument("-f", "--file", help="Test multiple URLs from file")

    parser.add_argument("--timeout", type=int, default=10, help="Request/browser timeout (seconds)")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for network/browser issues")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--only-vuln", action="store_true", help="Show only vulnerable results")
    parser.add_argument("--verbose", action="store_true", help="Show visible Chrome browser")
    parser.add_argument("--save-txt", metavar="FILE", help="Save output to a text file")

    args = parser.parse_args()

    if args.save_txt:
        LOG_FILE = args.save_txt
        open(LOG_FILE, "w").close()

    if args.url:
        targets = [args.url]
    else:
        with open(args.file, "r", encoding="utf-8") as f:
            targets = [x.strip() for x in f if x.strip()]

    for t in targets:
        try:
            check_one(
                t,
                timeout=args.timeout,
                retries=args.retries,
                no_verify=args.no_verify,
                headless=not args.verbose,
                only_vuln=args.only_vuln,
            )
        except Exception as e:
            log(f"[ERROR] {t} – {e}")


if __name__ == "__main__":
    main()
