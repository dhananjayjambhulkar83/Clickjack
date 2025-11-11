# clickjack

Small CLI tool to check whether a URL is framable (clickjacking test).  
Header-first checks (X-Frame-Options / CSP `frame-ancestors`), and—if headers are inconclusive—performs a safe browser verification using a local PoC HTML file.

> **Warning:** Only test systems you own or have explicit permission to test. Misuse may be illegal.

---

## Features

- Header-first detection using `requests` (fast).
- If headers are inconclusive, uses Firefox+GeckoDriver via Selenium to verify framability (no screenshots by default).
- Uses external `clickjacking.html` (you provide) — the script injects the tested URL into the first `<iframe>` tag.
- Automatic SSL fallback: verifies using `certifi` then retries silently with verification disabled for broken certs.
- Options to tune timeouts, retries and verbosity.
- `--only-vuln` to show only vulnerable URLs in output.

---

## Command-line options

-u/--url       Single URL to test
-f/--file      File containing URLs (one per line)
--timeout      Request/browser timeout (seconds). Default: 10
--retries      Number of retries for network/browser. Default: 2
--no-verify    Force skip SSL verification (overrides automatic fallback)
-v/--verbose   Show visible browser (manual confirmation)
--only-vuln    Print only vulnerable lines (suppress non-vuln/errors)

## Usage Example

# Single URL (headless)
python clickjack.py -u https://example.com

# Single URL with visible browser for manual inspection
python clickjack.py -u https://example.com -v

# File with multiple URLs
python clickjack.py -f targets.txt --timeout 30 --retries 3

# Show only vulnerable results
python clickjack.py -f targets.txt --only-vuln




