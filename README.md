# SecureScan

> A production-grade website security auditing suite built with Python and Flask. Instant 10-point passive security evaluations with real-world attack scenario breakdowns, executive PDF report exports, zero-backend session history, and a public JSON REST API.

---

## Live Demo
- **Web Application**: [https://project-secure-scan-20.vercel.app](https://project-secure-scan-20.vercel.app)
- **JSON REST API**: [https://project-secure-scan-20.vercel.app/api/scan?url=github.com](https://project-secure-scan-20.vercel.app/api/scan?url=github.com)
- **Engineering Notes & Known Limitations**: [https://project-secure-scan-20.vercel.app/notes](https://project-secure-scan-20.vercel.app/notes)

---

## Core Feature Suite

- **10-Point Threat-Driven Audit**: Comprehensive passive checks probing cryptography, access controls, browser defenses, DNS authentication, and info leaks. Every check explains the concrete attack scenario prevented.
- **Executive PDF Report Export**: High-contrast, publication-ready A4 PDF reports generated dynamically via pure-Python ReportLab with zero system dependencies.
- **Session Scan History**: Fast client-side quick switcher displaying the last 5 scans in the current browser session using `sessionStorage` (zero database, zero persistence).
- **Self-Rate-Limiting**: In-memory sliding-window limiter enforcing 10 scans/min per IP with honest cooldown guidance and standard `X-RateLimit-*` headers.
- **Public JSON REST API**: Programmatic `GET /api/scan?url=<target>` endpoint with unified audit logic, SSRF blocking, and explicit anti-bot challenge payloads.
- **Full WCAG AA Accessibility**: Keyboard-traversable session trays, universal high-visibility `:focus-visible` outlines, skip links, and verified color contrast (>= 4.5:1).

---

## The 10-Point Security Audit Matrix

SecureScan evaluates targets against real-world threat vectors, starting at 100 points and applying calibrated point deductions:

| # | Check | Category | Attack Scenario & Vulnerability Prevented | Max Deduction |
|---|---|---|---|---|
| 1 | **SSL/TLS Certificate Validity** | Transport Security | Certificate expiration, hostname mismatch, untrusted CA chain. Prevents Man-in-the-Middle (MitM) traffic interception and domain impersonation. | 20 pts |
| 2 | **TLS Protocol & Cipher Strength** | Transport Security | Probes deprecated TLS 1.0/1.1 and weak ciphers (<128-bit, 3DES, RC4). Defends against cryptographic downgrade attacks (POODLE, BEAST, Sweet32). | 15 pts |
| 3 | **HTTP Security Headers** | Browser Defense | Evaluates CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Stops XSS execution, SSL-stripping, clickjacking, and MIME confusion. | 15 pts |
| 4 | **CORS Misconfiguration** | Access Control | Analyzes `Access-Control-Allow-Origin` & `Allow-Credentials`. Flags dangerous wildcard/reflected origins with credentials that allow malicious sites to steal authenticated data. | 10 pts |
| 5 | **Cookie Security Flags** | Session Security | Audits `Secure`, `HttpOnly`, and `SameSite` flags. Prevents session token theft via XSS, plain-HTTP eavesdropping, and Cross-Site Request Forgery (CSRF). | 10 pts |
| 6 | **Mixed Content Detection** | Content Integrity | Scans HTML for active scripts/styles and passive media served over plain `http://` on HTTPS sites. Stops MitM script tampering and browser mixed-content blocks. | 10 pts |
| 7 | **Dangerous HTTP Methods** | Server Hardening | Evaluates `OPTIONS` responses and probes `TRACE`. Stops Cross-Site Tracing (XST) cookie harvesting and unauthorized remote file manipulations (`PUT`/`DELETE`). | 5 pts |
| 8 | **Email Spoofing Defense (SPF & DMARC)** | Domain & Identity | DNS TXT queries (dnspython & DNS-over-HTTPS fallback) inspecting SPF and enforcing DMARC policies (`p=reject`/`quarantine`). Stops Business Email Compromise (BEC) and executive spoofing. | 10 pts |
| 9 | **Sensitive File Exposure** | Information Disclosure | Probes for publicly exposed `/.env`, `/.git/config`, backup archives, and configurations. Prevents database credential dumps and source code exposure. | 10 pts |
| 10 | **Server Technology Fingerprinting** | Information Disclosure | Checks `Server` and `X-Powered-By` banners for software release versions. Slows down automated vulnerability scanners looking for matching unpatched CVEs. | 5 pts |

### Scoring & Grading Tiers
```text
Score = max(0, 100 - sum(deductions))
```
- **Grade A (90 – 100)**: Excellent security posture; modern defensive controls implemented.
- **Grade B (80 – 89)**: Good baseline security; minor configuration or hardening opportunities.
- **Grade C (65 – 79)**: Moderate risk; key browser defenses or email authentication missing.
- **Grade D (50 – 64)**: High risk; significant vulnerabilities or obsolete cryptography detected.
- **Grade F (0 – 49)**: Critical risk; urgent remediation required across multiple layers.

*(Sites that serve HTTP but properly redirect to HTTPS are not penalized for the initial HTTP hop — only genuinely insecure HTTP-only sites receive full deductions.)*

---

## Scope & Coverage

SecureScan is an automated, passive, read-only **configuration auditor** — it inspects what a web server exposes via standard, non-destructive HTTP requests, TLS cryptographic handshakes, and public DNS records.

It does **not** perform active or dynamic vulnerability testing (such as sending crafted, adversarial, or potentially exploitative payloads to identify application-layer flaws like XSS, SQL injection, or broken access control). Active vulnerability scanning is a different, more invasive category of security tooling (exemplified by tools like **Burp Suite**, **OWASP ZAP**, and **sqlmap**) and is intentionally outside this project's passive auditing scope.

### OWASP Category Mapping

| Category | Coverage | Why |
|---|---|---|
| XSS (Cross-Site Scripting) | Indirect only | We check whether a CSP defense exists, not whether the site actually has an exploitable XSS flaw. Confirming real XSS requires payload injection and observing execution, which this tool does not do. |
| SQL Injection (SQLi) | Not covered | Requires sending crafted input to parameters/forms and observing database-error behavior — active testing outside this tool's scope. |
| Security Misconfiguration | Covered | This is the tool's core strength: headers, CORS, cookies, dangerous HTTP methods, sensitive file exposure, and server fingerprinting are all checked directly. |
| Broken Access Control | Not covered | Requires testing authenticated flows (can user A reach user B's data, can a normal user reach admin routes). This tool has no concept of authentication/sessions to test against. |
| SSRF | Different direction | This tool protects ITSELF from being abused as an SSRF vector (blocks scanning internal/private addresses). It does not test whether the TARGET site is vulnerable to SSRF — that's the opposite check. |
| Outdated Components | Indirect only | Server fingerprinting can reveal a version banner, which could be manually cross-referenced against known CVEs, but this tool doesn't perform that lookup itself. |

---

## JSON REST API (`/api/scan`)

SecureScan includes a public, programmatic REST API endpoint for automation, CI/CD security assertions, and developer tooling.

### Endpoint
```http
GET /api/scan?url=<target>
```
*(Also accepts `POST` requests with form-encoded or JSON bodies).*

### Authentication & Rate Limiting
- **No API key required**.
- Subject to the same self-rate-limiter as the web interface: **10 scans per minute per IP**.
- Standard response headers:
  - `X-RateLimit-Limit`: Maximum requests allowed per window (10).
  - `X-RateLimit-Remaining`: Remaining requests available.
  - `Retry-After`: Cooldown in seconds before the next allowed request (on HTTP 429).

### Example `curl` Request
```bash
curl -s "https://project-secure-scan-20.vercel.app/api/scan?url=github.com"
```

### Sample Response (HTTP 200)
```json
{
  "url": "github.com",
  "final_url": "https://github.com/",
  "score": 94,
  "grade": "A",
  "timestamp": "2026-09-12 15:00 UTC",
  "checks": [
    {
      "name": "SSL/TLS Certificate Validity",
      "category": "Encryption & Transport",
      "passed": true,
      "deducted": 0,
      "explanation": "Certificate is valid and trusted (expires 2026-11-03, 52 days left). Issued by 'Let's Encrypt' for '*.github.com'.",
      "details": {
        "issuer": "Let's Encrypt",
        "common_name": "*.github.com",
        "days_left": 52,
        "expiry": "2026-11-03"
      }
    },
    {
      "name": "HTTP Security Headers",
      "category": "Application Defenses",
      "passed": false,
      "deducted": 1,
      "explanation": "Missing Permissions-Policy header. Attack Scenario: Missing Permissions-Policy allows third-party embedded frames to access device APIs.",
      "details": {
        "present": ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"],
        "missing": ["Permissions-Policy"]
      }
    }
  ]
}
```

### Structured Error Responses
- **Missing URL Parameter (HTTP 400)**:
  ```json
  {
    "error": "Missing URL parameter",
    "message": "Please provide a website URL to scan (e.g. /api/scan?url=example.com)",
    "status": 400
  }
  ```
- **Rate Limit Exceeded (HTTP 429)**:
  ```json
  {
    "error": "Rate limit exceeded",
    "message": "SecureScan limits scans to 10 per minute per IP. Please wait 45 seconds before scanning again.",
    "limit": 10,
    "retry_after": 45,
    "status": 429
  }
  ```
- **Bot-Protection Challenge (HTTP 403)**:
  ```json
  {
    "error": "Scan blocked by bot protection",
    "message": "Cloudflare Turnstile challenge detected",
    "url": "chatgpt.com",
    "bot_protection": {
      "provider": "Cloudflare",
      "mitigation": "challenge"
    },
    "status": 403
  }
  ```
- **SSRF Block (HTTP 400)**:
  ```json
  {
    "error": "Scan failed",
    "message": "This URL cannot be scanned. '127.0.0.1' resolves to a private or reserved IP address.",
    "url": "http://127.0.0.1",
    "status": 400
  }
  ```

---

## Tech Stack & Architecture

| Layer | Technology | Key Responsibility |
|---|---|---|
| **Backend Framework** | Python 3.9+, Flask 3.x | Routing, request lifecycle, rate limiting, and Jinja2 rendering |
| **Serverless Deployment** | Vercel Serverless Functions (`api/index.py`) | Microsecond cold starts, automatic HTTPS, global CDN edge routing |
| **PDF Generation** | ReportLab 3.x (Pure Python) | Serverless-compatible, standalone vector PDF document generator |
| **SSL/TLS & Ciphers** | pyOpenSSL, cryptography, Python ssl | X.509 chain inspection, protocol negotiation, cipher suite auditing |
| **DNS Security** | dnspython & Google / Cloudflare DoH | SPF and DMARC TXT record querying with DoH fallback |
| **HTTP Client** | requests (with streaming & timeout guards) | Safe outbound fetching, redirect-chain tracking, header auditing |
| **Frontend UI** | HTML5, Vanilla CSS, Vanilla JS | Zero external JavaScript frameworks, zero build step, pure speed |
| **Typography** | Inter (Google Fonts) | Clean, high-legibility modern sans-serif typeface |

---

## Security & Defense-in-Depth Design

### 1. SSRF Mitigation
- Only `http://` and `https://` schemes are permitted; `file://`, `gopher://`, `ftp://`, etc. are rejected immediately.
- Pre-request DNS resolution via `getaddrinfo` validates **all IPv4 and IPv6** records.
- Blocks RFC 1918 private subnets, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.169.254` AWS metadata), carrier-grade NAT (`100.64.0.0/10`), and multicast ranges.
- Re-validates the final URL after following redirect chains (capped at 10 hops) to prevent open-redirect SSRF pivoting.

### 2. Self-Protection & Host Hardening
SecureScan enforces on its own responses the exact security headers it audits on targets:
- `Content-Security-Policy`: Restricts scripts and styles to self and Google Fonts, frame-ancestors none.
- `Strict-Transport-Security`: Enforces HSTS with `max-age=31536000; includeSubDomains`.
- `X-Frame-Options: DENY` & `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: strict-origin-when-cross-origin`.
- `Permissions-Policy`: Blocks camera, microphone, geolocation, payment, and display-capture.

---

## Project Structure

```
SecureScan/
├── api/
│   └── index.py            ← Vercel serverless entry point (Flask app)
├── public/                 ← Production static assets (served via Vercel Edge CDN)
│   ├── css/
│   │   └── style.css       ← Dark UI stylesheet with WCAG AA compliance
│   └── js/
│       └── main.js         ← Scan form handling, session history, a11y keyboard controls
├── static/                 ← Local development static assets (mirrors public/)
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
├── templates/
│   ├── index.html          ← Homepage with clean scan form & session history tray
│   ├── results.html        ← Single-site audit card & check breakdowns
│   └── notes.html          ← Engineering notes & platform limitations
├── report_generator.py     ← Pure-Python ReportLab executive PDF generator
├── app.py                  ← Local development WSGI entry point (`python app.py`)
├── requirements.txt        ← Pinned Python dependencies
├── vercel.json             ← Vercel rewrite and function configuration
├── .python-version         ← Pins Python 3.9 runtime on Vercel
├── .vercelignore           ← Deployment exclusion rules
├── .env.example            ← Environment variable template
└── README.md
```

---

## Running Locally

### 1. Prerequisites
- Python 3.9 or higher
- `pip`

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/your-username/SecureScan.git
cd SecureScan

# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS / Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Development Server
```bash
python app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## Author & Academic Background

Built as the capstone practical project for a **BCA in Cybersecurity**.

Designed to demonstrate real-world secure software engineering:
- Automated vulnerability surface discovery without intrusive payload fuzzing.
- Protocol-level cryptographic inspection using low-level sockets and OpenSSL bindings.
- In-memory sliding-window rate limiting and defense against resource exhaustion.
- Serverless-compatible PDF document compiling with zero system binaries.
- Inclusive design adhering to WCAG 2.1 AA accessibility standards.

*SecureScan — BCA Cybersecurity Portfolio Project*
