#!/usr/bin/env python3
"""
clickjack.py - uses external clickjacking.html 

Requirements:
 - Place a file named `clickjacking.html` in the same folder as this script.
   That file must contain an <iframe> element (id not required). The script
   will replace the first iframe's src attribute with the tested URL.

Usage:
  python clickjack.py -u https://example.com
  python clickjack.py -f urls.txt --timeout 30 --retries 3 -v
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
from requests.exceptions import RequestException, SSLError, ConnectTimeout, ConnectionError

from selenium import webdriver
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FxOptions
from selenium.webdriver.firefox.service import Service as FxService
from webdriver_manager.firefox import GeckoDriverManager

# Silence InsecureRequestWarning when falling back to verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Config ----------
USER_AGENT = "clickjack-externalhtml/1.0"
LOCAL_POC_NAME = "clickjacking.html"   # external file required in current dir
POC_DIR = ".clickjack_pocs"            # not used for PoC generation when external file exists
SCREENSHOT_THRESHOLD_BYTES = 1024      # not used (no screenshots)

# ---------- Helpers ----------
def ensure_scheme_try_both(target: str) -> List[str]:
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', target):
        return [target]
    return [f"https://{target}", f"http://{target}"]

def parse_xfo(v: Optional[str]) -> Optional[str]:
    if not v: return None
    v_up = v.strip().upper()
    if "DENY" in v_up: return "DENY"
    if "SAMEORIGIN" in v_up: return "SAMEORIGIN"
    if "ALLOW-FROM" in v_up: return "ALLOW-FROM"
    return v_up

def headers_block_framing(headers: Dict[str, str]) -> Tuple[bool, str]:
    xfo = headers.get("X-Frame-Options") or headers.get("x-frame-options")
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
    if xfo:
        px = parse_xfo(xfo)
        if px in ("DENY", "SAMEORIGIN") or px == "ALLOW-FROM":
            return True, f"Header blocks framing: X-Frame-Options={xfo}"
    if csp and "frame-ancestors" in csp.lower():
        return True, "Header blocks framing: CSP frame-ancestors present"
    return False, "No blocking headers"

def start_firefox(visible: bool) -> webdriver.Firefox:
    opts = FxOptions()
    if not visible:
        opts.add_argument("--headless")
    opts.set_preference("general.useragent.override", USER_AGENT)
    gecko = GeckoDriverManager().install()
    service = FxService(gecko)
    driver = webdriver.Firefox(service=service, options=opts)
    return driver

# ---------- External PoC handling ----------
def prepare_external_poc(target_url: str) -> str:
    """
    Require an external file named clickjacking.html in current dir.
    Update its first iframe's src attribute to the target_url and return absolute path.
    If no iframe exists in file, append one.
    """
    cwd_poc = os.path.join(os.getcwd(), LOCAL_POC_NAME)
    if not os.path.exists(cwd_poc):
        raise FileNotFoundError(f"Required file '{LOCAL_POC_NAME}' not found in current directory.")
    # read and update
    try:
        with open(cwd_poc, "r", encoding="utf-8") as fh:
            content = fh.read()
    except Exception as e:
        raise RuntimeError(f"Unable to read {LOCAL_POC_NAME}: {e}")
    # find first iframe: replace its src or insert iframe if none
    iframe_pattern = re.compile(r'(<iframe\b[^>]*\bsrc\s*=\s*")[^"]*(")', flags=re.IGNORECASE)
    if iframe_pattern.search(content):
        new_content = iframe_pattern.sub(r'\1' + target_url + r'\2', content, count=1)
    else:
        # attempt to insert an iframe before closing </body> or at end
        iframe_html = f'\n<iframe id="cjframe" src="{target_url}" width="1000" height="700" style="border:3px solid #333;"></iframe>\n'
        if "</body>" in content.lower():
            # replace case-insensitive
            new_content = re.sub(r'</body>', iframe_html + '</body>', content, flags=re.IGNORECASE, count=1)
        else:
            new_content = content + iframe_html
    # write back
    try:
        with open(cwd_poc, "w", encoding="utf-8") as fh:
            fh.write(new_content)
    except Exception as e:
        raise RuntimeError(f"Unable to write updated {LOCAL_POC_NAME}: {e}")
    return os.path.abspath(cwd_poc)

# Friendly network error messages and suggestions
def friendly_network_error(target: str, exc: Exception, only_vuln: bool) -> None:
    text = str(exc)
    lower = text.lower()
    dns_indicators = ["name or service not known", "getaddrinfo failed", "failed to resolve", "nodename nor servname provided", "no address associated"]
    if any(ind in lower for ind in dns_indicators):
        if not only_vuln:
            print(f"[ERROR] {target} – unreachable: DNS resolution failed (could not resolve hostname).")
            print(f"  Suggestion: run `nslookup {target}` or try a different network / DNS server.")
        return
    if isinstance(exc, ConnectTimeout) or "timed out" in lower:
        if not only_vuln:
            print(f"[ERROR] {target} – unreachable: connection timed out (no TCP response).")
            print("  Suggestion: retry with a longer timeout (e.g. --timeout 30) or increase retries (e.g. --retries 3).")
            print(f"  Tip: if it works in a browser but not here, try from another network (VPN).")
        return
    if isinstance(exc, SSLError) or "certificate verify failed" in lower:
        if not only_vuln:
            print(f"[ERROR] {target} – unreachable: SSL verification failed.")
            print("  Suggestion: the tool will retry with certificate verification disabled silently; you can also use --no-verify.")
        return
    if isinstance(exc, ConnectionError) or "connection refused" in lower or "connection aborted" in lower:
        if not only_vuln:
            print(f"[ERROR] {target} – unreachable: connection error ({text.splitlines()[0]}).")
            print("  Suggestion: check network, try --timeout 30 and --retries 3, or test from another network.")
        return
    if not only_vuln:
        print(f"[ERROR] {target} – unreachable: {text.splitlines()[0]}")
        print("  Suggestion: try increasing --timeout or --retries, or check network/DNS.")

# ---------- No-screenshot iframe check ----------
def iframe_render_check(poc_path: str, headless: bool, timeout: int, retries: int, verbose: bool) -> Tuple[bool, str]:
    last_err = None
    for attempt in range(retries + 1):
        driver = None
        try:
            driver = start_firefox(visible=not headless)
            nav_timeout = max(30, timeout * 2)
            driver.set_page_load_timeout(nav_timeout)
            file_url = f"file://{poc_path}"
            driver.get(file_url)
            time.sleep(1.0)
            # find iframe
            try:
                iframe = driver.find_element(By.ID, "cjframe")
            except Exception:
                try:
                    iframe = driver.find_element(By.TAG_NAME, "iframe")
                except Exception:
                    iframe = None
            if iframe is None:
                try: driver.quit()
                except Exception: pass
                return False, "No iframe element found in PoC"
            # try switch
            try:
                driver.switch_to.frame("cjframe")
                cur = driver.current_url or ""
                if not cur.startswith("file://"):
                    try: driver.quit()
                    except Exception: pass
                    return True, "Frame switched and current_url changed -> content loaded"
                else:
                    try: driver.quit()
                    except Exception: pass
                    return False, "Switched to frame but current_url is still PoC (not loaded)"
            except WebDriverException:
                try: driver.quit()
                except Exception: pass
                return True, "Switch-to-frame raised WebDriverException (treated as cross-origin -> likely framable)"
        except (WebDriverException, TimeoutException) as e:
            last_err = e
            try:
                if driver: driver.quit()
            except Exception:
                pass
            time.sleep(1)
            continue
    if last_err:
        return False, f"Browser error: {str(last_err).splitlines()[0]}"
    return False, "Unknown browser error"

# ---------- Core check with silent SSL fallback ----------
def check_one_target(target: str, timeout: int, retries: int, force_no_verify_flag: bool, headless: bool, only_vuln: bool, verbose: bool) -> None:
    target = target.strip()
    if not target:
        return

    used_url = None
    headers: Dict[str, str] = {}
    last_exc: Optional[Exception] = None

    for candidate in ensure_scheme_try_both(target):
        attempt = 0
        while attempt <= retries:
            try:
                verify_arg = False if force_no_verify_flag else certifi.where()
                resp = requests.get(candidate,
                                    headers={"User-Agent": USER_AGENT},
                                    timeout=timeout,
                                    allow_redirects=True,
                                    verify=verify_arg)
                used_url = candidate
                headers = {k: v for k, v in resp.headers.items()}
                break
            except SSLError as ssle:
                last_exc = ssle
                # silent fallback
                try:
                    resp = requests.get(candidate,
                                        headers={"User-Agent": USER_AGENT},
                                        timeout=timeout,
                                        allow_redirects=True,
                                        verify=False)
                    used_url = candidate
                    headers = {k: v for k, v in resp.headers.items()}
                    break
                except RequestException as re_exc:
                    last_exc = re_exc
                    attempt += 1
                    time.sleep(1)
                    continue
            except (ConnectTimeout, ConnectionError, RequestException) as rexc:
                last_exc = rexc
                attempt += 1
                time.sleep(1)
                continue
        if used_url:
            break

    if not used_url:
        friendly_network_error(target, last_exc if last_exc else Exception("no response"), only_vuln)
        return

    blocked, reason = headers_block_framing(headers)
    if blocked:
        if not only_vuln:
            print(f"[NOT VULNERABLE] {used_url} – {reason}")
        return

    # prepare PoC using external clickjacking.html (required)
    try:
        poc_path = prepare_external_poc(used_url)
    except FileNotFoundError as fnf:
        if not only_vuln:
            print(f"[ERROR] missing PoC file: {LOCAL_POC_NAME} not found in current directory.")
            print("  Place your external PoC file named 'clickjacking.html' in the same folder as this script.")
        return
    except Exception as e:
        if not only_vuln:
            print(f"[ERROR] {used_url} – failed to prepare external PoC ({str(e).splitlines()[0]})")
        return

    framable, obs = iframe_render_check(poc_path, headless=headless, timeout=timeout, retries=retries, verbose=verbose)
    if framable:
        print(f"[VULNERABLE] {used_url}")
    else:
        if not only_vuln:
            print(f"[NOT VULNERABLE] {used_url} – {obs}")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        prog="clickjack",
        description="Clickjacking framability checker"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL or domain to test")
    group.add_argument("-f", "--file", help="File with URLs (one per line)")
    parser.add_argument("--timeout", type=int, default=10, help="Request/browser timeout in seconds (default 10). Increase for slow hosts.")
    parser.add_argument("--retries", type=int, default=2, help="Number of retries for network/browser checks (default 2).")
    parser.add_argument("--no-verify", action="store_true", help="Force skip SSL verification from the start (overrides automatic fallback)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Visible browser for manual confirmation (keeps window open until closed)")
    parser.add_argument("--only-vuln", action="store_true", help="Print only vulnerable lines (suppress non-vuln and errors)")
    args = parser.parse_args()

    if not args.only_vuln:
        print("Note: Only test sites you own or have permission to test.\n")
        print("Hints: if a host is slow/unreachable try: --timeout 30 --retries 3\n")

    targets = []
    if args.url:
        targets = [args.url.strip()]
    else:
        if not os.path.exists(args.file):
            print(f"[ERROR] file not found: {args.file}")
            sys.exit(2)
        with open(args.file, "r", encoding="utf-8") as fh:
            targets = [line.strip() for line in fh if line.strip()]

    for t in targets:
        try:
            check_one_target(t,
                             timeout=args.timeout,
                             retries=args.retries,
                             force_no_verify_flag=args.no_verify,
                             headless=not args.verbose,
                             only_vuln=args.only_vuln,
                             verbose=args.verbose)
        except KeyboardInterrupt:
            if not args.only_vuln:
                print("\nInterrupted by user.")
            break
        except Exception as e:
            if not args.only_vuln:
                print(f"[ERROR] {t} – {str(e).splitlines()[0]}")

if __name__ == "__main__":
    main()
