#!/usr/bin/env python3
"""
clickjack.py - uses external clickjacking.html

Note:
- Requires a file named `clickjacking.html` in the same directory.
- That file should contain an <iframe> (or the script will inject one).
"""

from __future__ import annotations
import argparse
import os
import re
import sys
import time
import urllib3
from typing import Dict, List, Optional, Tuple

import certifi
import requests
from requests.exceptions import (
    RequestException,
    SSLError,
    ConnectTimeout,
    ConnectionError,
)

from selenium import webdriver
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.common.by import By

# ----- Chrome -----
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Config ----------
USER_AGENT = "clickjack-externalhtml/1.0"
LOCAL_POC_NAME = "clickjacking.html"


# ---------- HELPERS ----------
def ensure_scheme_try_both(t: str) -> List[str]:
    """If URL has no scheme, try https:// and http://."""
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', t):
        return [t]
    return [f"https://{t}", f"http://{t}"]


def parse_xfo(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v_up = v.strip().upper()
    if "DENY" in v_up:
        return "DENY"
    if "SAMEORIGIN" in v_up:
        return "SAMEORIGIN"
    if "ALLOW-FROM" in v_up:
        return "ALLOW-FROM"
    return v_up


def headers_block_framing(headers: Dict[str, str]):
    """Return (blocked: bool, reason: str) based on XFO / CSP."""
    xfo = headers.get("X-Frame-Options") or headers.get("x-frame-options")
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")

    if xfo:
        px = parse_xfo(xfo)
        if px in ("DENY", "SAMEORIGIN", "ALLOW-FROM"):
            return True, f"Header blocks framing: X-Frame-Options={xfo}"

    if csp and "frame-ancestors" in csp.lower():
        return True, "Header blocks framing: CSP frame-ancestors present"

    return False, "No blocking headers"


# ---------- BROWSER ----------
def start_browser(visible: bool):
    """Start Chrome using webdriver-manager."""
    opts = ChromeOptions()
    if not visible:
        opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument(f"--user-agent={USER_AGENT}")

    chrome_path = ChromeDriverManager().install()
    service = ChromeService(chrome_path)
    return webdriver.Chrome(service=service, options=opts)


# ---------- PoC ----------
def prepare_external_poc(target_url: str) -> str:
    """
    Use clickjacking.html in current dir.
    - Replace first iframe src with target_url, or
    - Inject new iframe if none exist.
    """
    poc = os.path.join(os.getcwd(), LOCAL_POC_NAME)
    if not os.path.exists(poc):
        raise FileNotFoundError(f"{LOCAL_POC_NAME} not found in current directory.")

    with open(poc, "r", encoding="utf-8") as f:
        content = f.read()

    iframe_pattern = re.compile(r'(<iframe\b[^>]*\bsrc\s*=\s*")[^"]*(")', re.IGNORECASE)

    if iframe_pattern.search(content):
        new = iframe_pattern.sub(r'\1' + target_url + r'\2', content, count=1)
    else:
        iframe = (
            f'\n<iframe id="cjframe" src="{target_url}" width="1000" height="700" '
            f'style="border:3px solid #333;"></iframe>\n'
        )
        if "</body>" in content.lower():
            new = re.sub(r'</body>', iframe + "</body>", content, flags=re.IGNORECASE)
        else:
            new = content + iframe

    with open(poc, "w", encoding="utf-8") as f:
        f.write(new)

    return poc


# ---------- FRAME CHECK ----------
def iframe_render_check(poc_path: str, headless: bool, timeout: int, retries: int, verbose: bool):
    """
    Load local PoC and see if we can successfully switch into iframe.
    If yes => page is framable => VULNERABLE.
    """
    last_error = None

    for attempt in range(retries + 1):
        driver = None
        try:
            driver = start_browser(visible=not headless)
            driver.set_page_load_timeout(max(30, timeout * 2))

            driver.get(f"file://{poc_path}")
            time.sleep(1)

            # Find iframe
            try:
                iframe = driver.find_element(By.ID, "cjframe")
            except Exception:
                try:
                    iframe = driver.find_element(By.TAG_NAME, "iframe")
                except Exception:
                    iframe = None

            if iframe is None:
                driver.quit()
                return False, "No iframe found in PoC"

            # If switching into the iframe works => page is framable
            try:
                try:
                    driver.switch_to.frame("cjframe")
                except Exception:
                    driver.switch_to.frame(iframe)

                # Try to find body (may fail for cross-origin but still means frame loaded)
                try:
                    driver.find_element(By.TAG_NAME, "body")
                except Exception:
                    pass

                driver.quit()
                return True, "Iframe loaded successfully → framable"

            except WebDriverException:
                driver.quit()
                return False, "Browser prevented switching → not framable"

        except Exception as e:
            last_error = e
            if driver:
                driver.quit()
            time.sleep(1)
            continue

    return False, f"Browser error: {last_error}"


# ---------- TARGET CHECK ----------
def check_one(
    target: str, timeout: int, retries: int, no_verify: bool, headless: bool, only_vuln: bool, verbose: bool
):
    target = target.strip()
    if not target:
        return

    used_url = None
    headers: Dict[str, str] = {}
    last_exc: Optional[Exception] = None

    # Try HTTPS/HTTP
    for url in ensure_scheme_try_both(target):
        attempt = 0
        while attempt <= retries:
            try:
                # primary attempt: normal verification (unless --no-verify)
                verify_arg = False if no_verify else certifi.where()
                resp = requests.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=timeout,
                    verify=verify_arg,
                    allow_redirects=True,
                )
                used_url = url
                headers = resp.headers
                break

            except SSLError as ssl_err:
                # automatic fallback: retry ONCE for this attempt with verify=False
                last_exc = ssl_err
                try:
                    resp = requests.get(
                        url,
                        headers={"User-Agent": USER_AGENT},
                        timeout=timeout,
                        verify=False,
                        allow_redirects=True,
                    )
                    used_url = url
                    headers = resp.headers
                    break
                except Exception as e2:
                    last_exc = e2
                    attempt += 1
                    time.sleep(1)
                    continue

            except (ConnectTimeout, ConnectionError, RequestException) as e:
                last_exc = e
                attempt += 1
                time.sleep(1)
                continue

        if used_url:
            break

    # ---------- LABELED ERROR OUTPUT ----------
    if not used_url:
        if not only_vuln:
            msg = (str(last_exc) or "").lower()

            if "timed out" in msg or "timeout" in msg:
                print(f"[TIMEOUT] {target} – Site not responding (connection timeout)")
            elif "certificate" in msg or "ssl" in msg:
                print(f"[SSL ERROR] {target} – SSL validation failed")
            elif "failed to establish" in msg or "connection" in msg or "refused" in msg:
                print(f"[UNREACHABLE] {target} – Network error / site not responding")
            else:
                print(f"[ERROR] {target} – {last_exc}")
        return

    # Header check
    blocked, reason = headers_block_framing(headers)
    if blocked:
        if not only_vuln:
            print(f"[NOT VULNERABLE] {used_url} – {reason}")
        return

    # PoC injection
    try:
        poc = prepare_external_poc(used_url)
    except Exception as e:
        if not only_vuln:
            print(f"[ERROR] {used_url} – Failed PoC creation: {e}")
        return

    # Browser test
    vuln, message = iframe_render_check(poc, headless, timeout, retries, verbose)

    if vuln:
        print(f"[VULNERABLE] {used_url}")
    else:
        if not only_vuln:
            print(f"[NOT VULNERABLE] {used_url} – {message}")


# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL to test")
    group.add_argument("-f", "--file", help="File with URLs (one per line)")

    p.add_argument("--timeout", type=int, default=10, help="Request timeout (default 10s)")
    p.add_argument("--retries", type=int, default=2, help="Number of retries on network errors")
    p.add_argument("--no-verify", action="store_true", help="Force disable SSL verification for all requests")
    p.add_argument("-v", "--verbose", action="store_true", help="Show real browser instead of headless")
    p.add_argument("--only-vuln", action="store_true", help="Only print [VULNERABLE] lines")

    a = p.parse_args()

    if not a.only_vuln:
        print("Note: Only test sites you own or have permission to test.\n")
        print("Hints: if a host is slow/unreachable try: --timeout 30 --retries 3\n")

    if a.url:
        targets = [a.url]
    else:
        with open(a.file, "r", encoding="utf-8") as f:
            targets = [x.strip() for x in f.readlines() if x.strip()]

    for t in targets:
        try:
            check_one(
                t,
                timeout=a.timeout,
                retries=a.retries,
                no_verify=a.no_verify,
                headless=not a.verbose,
                only_vuln=a.only_vuln,
                verbose=a.verbose,
            )
        except KeyboardInterrupt:
            break
        except Exception as e:
            if not a.only_vuln:
                print(f"[ERROR] {t} – {e}")


if __name__ == "__main__":
    main()
