# 🕵️‍♂️ clickjack

Small CLI tool to check whether a URL is **framable** (clickjacking test).  
Performs fast header-first checks (`X-Frame-Options` / CSP `frame-ancestors`) and — if headers are inconclusive — performs a safe browser verification using a local PoC HTML file.

> ⚠️ **Warning:** Only test systems you own or have explicit permission to test. Misuse may be illegal.

---

## ✨ Features

✅ Header-first detection using `requests` (fast)  
🧠 Safe browser verification with Firefox + GeckoDriver via Selenium (if headers inconclusive)  
🧩 External `clickjacking.html` PoC — script injects tested URL into first `<iframe>`  
🔐 Automatic SSL fallback: verifies using `certifi`, retries silently with disabled verification  
⚙️ Configurable timeouts, retries, and verbosity  
🎯 `--only-vuln` to output only vulnerable URLs (clean, automation-ready output)

---

## 🧱 Requirements

- 🐍 Python **3.8+**
- 🦊 Firefox browser
- ⚙️ GeckoDriver (must be in your PATH)
- 📦 Python packages from `requirements.txt`

---

## 📦 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/dhananjayjambhulkar83/Clickjack
cd clickjack
```

### 2️⃣ Install dependencies
```bash
pip3 install -r requirements.txt
```

---

## 🧠 Usage

🔹 Single URL (headless)
```
python clickjack.py -u https://example.com
```

🔹 Visible browser for manual inspection
```
python clickjack.py -u https://example.com -v
```

🔹 Multiple URLs from file
```
python clickjack.py -f targets.txt --timeout 30 --retries 3
```

🔹 Only vulnerable results 
```
python clickjack.py -f targets.txt --only-vuln
```
---

## ⚙️ Command-Line Options

| 🔧 Option | Description |
|---|---|
| `-u, --url` | Single URL to test |
| `-f, --file` | File containing URLs (one per line) |
| `--timeout` | Request/browser timeout (seconds). **Default:** 10 |
| `--retries` | Number of retries for network/browser. **Default:** 2 |
| `--no-verify` | Skip SSL verification |
| `-v, --verbose` | Show visible browser (manual inspection) |
| `--only-vuln` | Show only vulnerable results |

---


## 🧩 How It Works

1.🔍 Sends an HTTP request and checks:
      
      - X-Frame-Options
      - Content-Security-Policy: frame-ancestor

2.🧠 If headers deny framing → Not framable.

3.🧪 If headers missing/inconclusive → Launches headless Firefox:

    - Loads PoC HTML
    - Injects target URL into <iframe>
    - Detects frame errors or success

4.✅ Prints results — optionally only vulnerabilities (--only-vuln).
