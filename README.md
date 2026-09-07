# SecureScan

> A lightweight website security auditor built with Python and Flask — instant checks for HTTP headers, SSL/TLS, cookies, server info leakage, and exposed sensitive files.

---

## Screenshot

<!-- Replace this placeholder with your own screenshot once the app is running -->
![SecureScan homepage screenshot](screenshot.png)

---

## What it checks

| # | Check | What it tests | Max deduction |
|---|---|---|---|
| 1 | **HTTP Security Headers** | Presence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | 60 pts |
| 2 | **SSL / TLS Certificate** | Certificate validity, expiry date, issuer, days remaining | 30 pts |
| 3 | **Cookie Security Flags** | Each cookie audited for `Secure`, `HttpOnly`, and `SameSite` flags | 20 pts |
| 4 | **Server Info Leakage** | Whether `Server`, `X-Powered-By`, etc. expose software names or version numbers | 10 pts |
| 5 | **Sensitive File Exposure** | Probes for publicly accessible `.env`, `.git/config`, `wp-config.php`, and 6 other common paths | 20 pts |

Scoring starts at 100 and deducts points per failed check. Final score maps to a letter grade:

| Grade | Score |
|---|---|
| A | 90 – 100 |
| B | 80 – 89 |
| C | 65 – 79 |
| D | 50 – 64 |
| F | 0 – 49 |

Sites that serve HTTP but properly redirect to HTTPS are **not penalised** for the missing HTTPS — only genuinely HTTP-only sites take the heavier deduction.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.9+, Flask 3.x |
| Deployment | Vercel Serverless Functions (`api/index.py`), WSGI / Gunicorn |
| SSL inspection | pyOpenSSL, cryptography |
| HTTP client | requests |
| Frontend | Plain HTML5, Vanilla CSS, Vanilla JS — zero frameworks |
| Fonts | Inter (Google Fonts) |

No database. No login. No build step.

---

## Running locally

### Prerequisites

- Python 3.9 or later
- `pip`

### Setup

```bash
# Clone the repository
git clone https://github.com/your-username/SecureScan.git
cd SecureScan

# Create a virtual environment (recommended)
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## Deployment (Vercel)

SecureScan is pre-configured for one-click deployment on **Vercel**:

- **Serverless API:** `api/index.py` handles backend scanning via Flask within Vercel's serverless runtime.
- **Static Assets:** `public/` is served directly from Vercel's Edge CDN at root paths (`/css/style.css`, `/js/main.js`).
- **Routing:** `vercel.json` rewrites web requests to `api/index.py` while letting static assets serve directly from CDN.

To deploy via GitHub:
1. Push this repository to GitHub.
2. Import the repository in your [Vercel Dashboard](https://vercel.com/new).
3. Vercel automatically detects the Python runtime and deploys without extra build steps.

---

## Security design notes

SecureScan applies defense-in-depth principles:

### SSRF Protection
- Only `http://` and `https://` schemes are accepted — `file://`, `ftp://`, etc. are rejected immediately.
- The submitted hostname is resolved via `getaddrinfo` (which returns all IPv4 **and** IPv6 records) before any HTTP request is made.
- Every resolved IP is checked against a blocklist covering RFC 1918 private ranges, loopback (`127.0.0.0/8`, `::1`), link-local (including `169.254.169.254` — the AWS metadata endpoint), carrier-grade NAT, and reserved blocks.
- After following any redirect chain (capped at 10 hops), the final URL is validated a second time to block open-redirect-to-internal attacks.

### Built-in Hardening
SecureScan enforces the exact same security headers it tests on its own responses via Flask's `@app.after_request`:
- `Content-Security-Policy`: Strict policy restricting script execution to self, Google Fonts styles and fonts, and disallowing framing (`frame-ancestors 'none'`).
- `Strict-Transport-Security`: HSTS enabled with `max-age=31536000; includeSubDomains`.
- `X-Frame-Options`: Set to `DENY` to prevent clickjacking.
- `X-Content-Type-Options`: Set to `nosniff` to prevent MIME-confusion attacks.
- `Referrer-Policy`: `strict-origin-when-cross-origin`.
- `Permissions-Policy`: Restrictive policy denying unused browser hardware features (camera, microphone, geolocation).

---

## Project structure

```
SecureScan/
├── api/
│   └── index.py          ← Vercel serverless entry point (Flask app)
├── public/               ← Production static assets (served via Vercel Edge CDN)
│   ├── css/
│   │   └── style.css     ← Modern dark UI stylesheet
│   └── js/
│       └── main.js       ← Loading state, score counter animation, detail toggles
├── static/               ← Local development static assets (mirrors public/)
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
├── templates/
│   ├── index.html        ← Homepage & scan submission form
│   └── results.html      ← Security score card & detailed check breakdowns
├── .env.example          ← Template for optional environment variables
├── .gitignore            ← Excludes local secrets, cache, and scratch scripts
├── .python-version       ← Pins Python runtime on Vercel
├── .vercelignore         ← Excludes non-essential directories from Vercel deployment
├── app.py                ← Local development entry point (`python app.py`)
├── requirements.txt      ← Python package dependencies
├── vercel.json           ← Vercel rewrite & execution configuration
└── README.md
```

---

## Why I built this

This project was built as the first practical piece of my BCA in Cybersecurity.

I wanted a tool that does what I actually care about as a developer and security student: quickly telling you **what's wrong with a site's security posture** without needing to run nmap, read raw curl output, or pay for a SaaS scanner.

The goal was to make the output legible to a non-technical audience — a recruiter or hiring manager should be able to look at the results page and understand *why* a missing `Content-Security-Policy` matters, not just that it's absent. The plain-English explanations in every check card are deliberate.

It also gave me hands-on experience with:

- **HTTP security header analysis** — understanding what each header does at the protocol level
- **SSL/TLS inspection** with pyOpenSSL — parsing X.509 certificates, checking validity windows
- **SSRF mitigation** — DNS resolution before request, blocking private IP ranges, post-redirect validation
- **Secure cookie auditing** — parsing raw `Set-Cookie` headers for `Secure`, `HttpOnly`, `SameSite`
- **Server-side Python** — Flask routing, error handling, Jinja2 templating, and Vercel serverless deployment

---

*SecureScan — BCA Cybersecurity Portfolio Project*
