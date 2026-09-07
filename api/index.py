import os
import re
import ssl
import socket
import datetime
import ipaddress
from typing import Optional
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request, jsonify, redirect
from OpenSSL import crypto

# Resolve paths relative to this file so Vercel can find templates
# regardless of what directory it invokes the function from.
_HERE      = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES = os.path.join(_HERE, "..", "templates")

app = Flask(__name__, template_folder=_TEMPLATES)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# ─────────────────────────────────────────────────────────────────────────────
# Constants & helpers
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.htaccess",
    "/web.config",
    "/config.php",
    "/.DS_Store",
    "/phpinfo.php",
    "/wp-config.php",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "points": 15,
        "description": "Restricts which resources (scripts, images, etc.) the browser can load. "
                       "Prevents Cross-Site Scripting (XSS) attacks.",
    },
    "Strict-Transport-Security": {
        "points": 15,
        "description": "Forces browsers to use HTTPS for future visits. Prevents protocol downgrade "
                       "and cookie hijacking attacks.",
    },
    "X-Frame-Options": {
        "points": 10,
        "description": "Stops your page from being embedded in iframes on other sites. "
                       "Prevents clickjacking attacks.",
    },
    "X-Content-Type-Options": {
        "points": 10,
        "description": "Prevents browsers from guessing (sniffing) the file type of a response. "
                       "Stops certain XSS and drive-by download attacks.",
    },
    "Referrer-Policy": {
        "points": 5,
        "description": "Controls how much referrer information is sent with requests. "
                       "Protects user privacy and prevents info leakage.",
    },
    "Permissions-Policy": {
        "points": 5,
        "description": "Controls access to browser features (camera, microphone, location, etc.). "
                       "Reduces your site's attack surface.",
    },
}

GRADE_MAP = [
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (0,  "F"),
]


def score_to_grade(score: int) -> str:
    for threshold, grade in GRADE_MAP:
        if score >= threshold:
            return grade
    return "F"


# ─────────────────────────────────────────────────────────────────────────────
# SSRF Protection
# ─────────────────────────────────────────────────────────────────────────────

# All IP ranges that must never be contacted
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # this network
    ipaddress.ip_network("10.0.0.0/8"),          # private class A
    ipaddress.ip_network("100.64.0.0/10"),       # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),       # private class B
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),      # private class C
    ipaddress.ip_network("198.18.0.0/15"),       # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),         # reserved
    # IPv6 equivalents
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
]


def is_ip_blocked(ip_str: str) -> bool:
    """Return True if the IP falls in any blocked/private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        # Built-in shortcuts
        if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
            return True
        # Explicit network list (catches ranges not covered by the flags above)
        for net in BLOCKED_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return True  # unparseable → block by default


def validate_ssrf(url: str) -> tuple:
    """
    Returns (is_safe: bool, error_message: str).
    Resolves ALL IP addresses for the hostname (IPv4 + IPv6) and rejects
    any that fall in private/internal/reserved ranges.
    Also rejects non-http(s) schemes.
    """
    parsed = urlparse(url)

    # 1. Scheme must be http or https
    if parsed.scheme not in ("http", "https"):
        return False, (
            f"Scheme '{parsed.scheme}://' is not supported. "
            "Only http:// and https:// URLs can be scanned."
        )

    hostname = parsed.hostname
    if not hostname:
        return False, "Could not extract a hostname from the URL."

    # 2. DNS resolution — getaddrinfo returns ALL addresses (IPv4 & IPv6)
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, (
            f"Could not resolve '{hostname}' to an IP address. "
            "Check the domain name and try again."
        )
    except OSError as e:
        return False, f"DNS lookup failed for '{hostname}': {str(e)[:120]}"

    if not results:
        return False, f"No IP addresses found for '{hostname}'."

    # 3. Check every resolved address
    for family, _type, _proto, _canon, sockaddr in results:
        ip_str = sockaddr[0]  # (ip, port) or (ip, port, flow, scope)
        if is_ip_blocked(ip_str):
            return False, (
                f"This URL cannot be scanned. '{hostname}' resolves to "
                f"{ip_str}, which is a private or reserved IP address. "
                "Scanning internal network addresses is not permitted."
            )

    return True, ""


def normalize_url(raw: str) -> Optional[str]:
    """
    Add https:// scheme if missing; validate structural shape.
    IP/SSRF checks are handled separately by validate_ssrf().
    """
    raw = raw.strip()
    if not raw:
        return None
    # Strip any unsupported scheme to avoid passing file://, ftp://, etc.
    if "://" in raw and not raw.startswith(("http://", "https://")):
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc or not parsed.hostname:
        return None
    return raw


def safe_get(url: str, timeout: int = 9, allow_redirects: bool = True) -> requests.Response:
    """
    HTTP GET with a shared session, explicit timeout, redirect cap,
    and standard SSL verification (SSL errors are caught at call site).

    Timeout is set to 9 s (down from 12 s on the local dev server) to leave
    comfortable headroom under Vercel's serverless cold-start overhead while
    still waiting long enough for legitimately slow sites.
    """
    headers = {
        "User-Agent": "SecureScan/1.0 (security-audit; github.com/securescan)"
    }
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    session = requests.Session()
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.max_redirects = 10   # cap redirect chains at 10 hops
    return session.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=allow_redirects,
        verify=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# The 5 checks
# ─────────────────────────────────────────────────────────────────────────────

def check_security_headers(response_headers: dict) -> dict:
    """Check 1 – HTTP Security Headers"""
    present   = []
    missing   = []
    deducted  = 0

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in {k.lower() for k in response_headers}:
            present.append(header)
        else:
            missing.append(header)
            deducted += meta["points"]

    passed = len(missing) == 0
    max_possible_deduction = sum(m["points"] for m in SECURITY_HEADERS.values())

    detail_rows = []
    for header, meta in SECURITY_HEADERS.items():
        found = header.lower() in {k.lower() for k in response_headers}
        detail_rows.append({
            "name": header,
            "found": found,
            "points": meta["points"],
            "description": meta["description"],
        })

    if missing:
        explanation = (
            f"Missing {len(missing)} of {len(SECURITY_HEADERS)} security headers: "
            + ", ".join(missing) + ". "
            "These HTTP response headers are a first line of defence against common web attacks."
        )
    else:
        explanation = (
            "All major security headers are present. "
            "The server is correctly instructing browsers on security policy."
        )

    return {
        "name": "HTTP Security Headers",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "detail_rows": detail_rows,
    }


def check_ssl(hostname: str) -> dict:
    """Check 2 – SSL/TLS Certificate Validity"""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.create_connection((hostname, 443), timeout=8),
            server_hostname=hostname,
        )
        cert_der = conn.getpeercert(binary_form=True)
        conn.close()

        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
        not_after_str  = x509.get_notAfter().decode()
        not_before_str = x509.get_notBefore().decode()

        fmt = "%Y%m%d%H%M%SZ"
        not_after  = datetime.datetime.strptime(not_after_str,  fmt)
        not_before = datetime.datetime.strptime(not_before_str, fmt)
        now        = datetime.datetime.utcnow()

        days_left    = (not_after - now).days
        is_expired   = now > not_after
        not_yet      = now < not_before
        expires_soon = 0 < days_left <= 30

        issuer = dict(x509.get_issuer().get_components())
        issuer_name = issuer.get(b"O", b"Unknown").decode(errors="replace")
        subject     = dict(x509.get_subject().get_components())
        common_name = subject.get(b"CN", b"Unknown").decode(errors="replace")

        if is_expired:
            passed   = False
            deducted = 30
            explanation = (
                f"Certificate expired on {not_after.date()}. "
                "Browsers will show a scary warning page and block most users. "
                "Renew immediately."
            )
        elif not_yet:
            passed   = False
            deducted = 25
            explanation = (
                f"Certificate is not yet valid (valid from {not_before.date()}). "
                "This will cause browser SSL errors."
            )
        elif expires_soon:
            passed   = True
            deducted = 10
            explanation = (
                f"Certificate is valid but expires in {days_left} day(s) on {not_after.date()}. "
                "Schedule a renewal soon to avoid downtime."
            )
        else:
            passed   = True
            deducted = 0
            explanation = (
                f"Certificate is valid (expires {not_after.date()}, {days_left} days left). "
                f"Issued by {issuer_name} for {common_name}."
            )

        return {
            "name": "SSL/TLS Certificate",
            "passed": passed,
            "deducted": deducted,
            "explanation": explanation,
            "details": {
                "common_name": common_name,
                "issuer": issuer_name,
                "expires": str(not_after.date()),
                "days_left": days_left,
            },
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "name": "SSL/TLS Certificate",
            "passed": False,
            "deducted": 30,
            "explanation": (
                f"SSL certificate verification failed: {e.reason}. "
                "This could mean an untrusted CA, expired cert, or hostname mismatch."
            ),
        }
    except (ConnectionRefusedError, socket.timeout, OSError):
        return {
            "name": "SSL/TLS Certificate",
            "passed": False,
            "deducted": 20,
            "explanation": (
                "Could not connect to port 443. The site may not support HTTPS, "
                "or the connection was refused/timed out."
            ),
        }
    except Exception as e:
        return {
            "name": "SSL/TLS Certificate",
            "passed": False,
            "deducted": 15,
            "explanation": f"Unexpected SSL check error: {str(e)[:120]}",
        }


def check_cookies(response: requests.Response) -> dict:
    """Check 3 – Cookie Security Flags"""
    raw_cookies = response.cookies
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []

    # Fall back to case-insensitive scan of all headers
    if not set_cookie_headers:
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

    if not set_cookie_headers:
        return {
            "name": "Cookie Security Flags",
            "passed": True,
            "deducted": 0,
            "explanation": "No cookies were set by the server — nothing to flag.",
        }

    issues   = []
    deducted = 0
    cookie_details = []

    for raw in set_cookie_headers:
        raw_lower = raw.lower()
        name_match = re.match(r"([^=]+)=", raw)
        name = name_match.group(1).strip() if name_match else "unknown"

        has_secure   = "secure"   in raw_lower
        has_httponly = "httponly" in raw_lower
        has_samesite = "samesite" in raw_lower

        cookie_issues = []
        pts = 0
        if not has_secure:
            cookie_issues.append("missing Secure flag")
            pts += 4
        if not has_httponly:
            cookie_issues.append("missing HttpOnly flag")
            pts += 4
        if not has_samesite:
            cookie_issues.append("missing SameSite flag")
            pts += 2

        deducted += pts
        cookie_details.append({
            "name": name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": has_samesite,
            "issues": cookie_issues,
        })
        issues.extend([f"{name}: {i}" for i in cookie_issues])

    deducted = min(deducted, 20)   # cap total cookie deduction

    if issues:
        explanation = (
            f"{len(cookie_details)} cookie(s) found with flag issues. "
            "Missing Secure → cookie sent over plain HTTP. "
            "Missing HttpOnly → readable by JavaScript (XSS risk). "
            "Missing SameSite → vulnerable to CSRF attacks."
        )
        passed = False
    else:
        explanation = (
            f"All {len(cookie_details)} cookie(s) have Secure, HttpOnly, and SameSite flags set. "
            "Great defence against session hijacking and CSRF."
        )
        passed = True

    return {
        "name": "Cookie Security Flags",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "cookie_details": cookie_details,
    }


def check_server_leakage(response_headers: dict) -> dict:
    """Check 4 – Server Header Info Leakage"""
    leaky_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Generator", "X-Runtime"]

    found_leaks = {}
    for h in leaky_headers:
        for k, v in response_headers.items():
            if k.lower() == h.lower() and v.strip():
                found_leaks[k] = v

    # Check whether the value reveals version info (numbers in the string)
    version_pattern = re.compile(r"\d+[\.\d]*")
    reveals_version = any(version_pattern.search(v) for v in found_leaks.values())

    if not found_leaks:
        return {
            "name": "Server Info Leakage",
            "passed": True,
            "deducted": 0,
            "explanation": (
                "No server technology headers detected. "
                "The server isn't giving attackers a free roadmap of its software stack."
            ),
        }
    elif reveals_version:
        explanation = (
            "Server headers reveal software and version info: "
            + ", ".join(f"{k}: {v}" for k, v in found_leaks.items()) + ". "
            "Knowing exact versions lets attackers look up known CVEs for that release."
        )
        return {
            "name": "Server Info Leakage",
            "passed": False,
            "deducted": 10,
            "explanation": explanation,
            "leaks": found_leaks,
        }
    else:
        explanation = (
            "Server technology type is disclosed ("
            + ", ".join(f"{k}: {v}" for k, v in found_leaks.items())
            + ") but no version numbers are exposed. Low risk, but ideally suppress these headers."
        )
        return {
            "name": "Server Info Leakage",
            "passed": False,
            "deducted": 3,
            "explanation": explanation,
            "leaks": found_leaks,
        }


def check_sensitive_files(base_url: str) -> dict:
    """Check 5 – Exposed Sensitive Files"""
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    exposed = []
    for path in SENSITIVE_PATHS:
        try:
            resp = requests.get(
                base + path,
                timeout=5,
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": "SecureScan/1.0"},
            )
            if resp.status_code == 200 and len(resp.content) > 0:
                exposed.append(path)
        except Exception:
            continue

    if exposed:
        explanation = (
            f"Found {len(exposed)} publicly accessible sensitive file(s): "
            + ", ".join(exposed) + ". "
            "These files can expose credentials, server config, or internal paths. "
            "Block them via your web server config (nginx/Apache deny rules)."
        )
        deducted = min(len(exposed) * 10, 20)
        passed   = False
    else:
        explanation = (
            "None of the common sensitive files (.env, .git/config, etc.) "
            "are publicly accessible. Good."
        )
        deducted = 0
        passed   = True

    return {
        "name": "Sensitive File Exposure",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "exposed_paths": exposed,
    }


def check_https_redirect(url: str) -> Optional[dict]:
    """
    If the user supplied an HTTPS URL but the plain HTTP version redirects to HTTPS,
    returns None (no penalty).  If the site is HTTP-only, returns a penalty dict.
    """
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return None   # already HTTPS – no need to test redirect

    # User gave http:// — check if it redirects to https://
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
    try:
        resp = requests.get(http_url, timeout=8, allow_redirects=False,
                            headers={"User-Agent": "SecureScan/1.0"})
        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
            return None   # it redirects to HTTPS — no penalty
    except Exception:
        pass

    return {
        "name": "HTTPS / HTTP Redirect",
        "passed": False,
        "deducted": 20,
        "explanation": (
            "The site is served over plain HTTP and does not redirect to HTTPS. "
            "All traffic — including passwords and session cookies — is transmitted in "
            "clear text and can be intercepted. Enabling HTTPS is essential."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=(), display-capture=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        raw_url = request.args.get("url", "").strip()
        if not raw_url:
            return redirect("/")
    else:
        raw_url = request.form.get("url", "").strip()

    # ── Step 1: Basic structure validation ──────────────────────────────────
    if not raw_url:
        return render_template("index.html", error="Please enter a URL to scan.")

    url = normalize_url(raw_url)
    if url is None:
        return render_template(
            "index.html",
            error=(
                "Invalid URL format. Please enter a public web address "
                "(e.g. github.com or https://example.com). "
                "Only http:// and https:// URLs are supported."
            ),
            prefill=raw_url,
        )

    parsed   = urlparse(url)
    hostname = parsed.hostname

    # ── Step 2: SSRF — validate the URL resolves to a public IP ─────────────
    is_safe, ssrf_reason = validate_ssrf(url)
    if not is_safe:
        return render_template(
            "index.html",
            error=ssrf_reason,
            prefill=raw_url,
        )

    # ── Step 3: Fetch the target page ───────────────────────────────────────
    try:
        response  = safe_get(url, timeout=12)
        final_url = response.url
    except requests.exceptions.SSLError as e:
        return render_template(
            "index.html",
            error=(
                f"SSL error when connecting to {hostname}: the certificate may be "
                "invalid, expired, or self-signed. "
                f"Detail: {str(e)[:180]}"
            ),
            prefill=raw_url,
        )
    except requests.exceptions.ConnectionError:
        return render_template(
            "index.html",
            error=(
                f"Could not connect to '{hostname}'. "
                "The domain may not exist, or the server refused the connection."
            ),
            prefill=raw_url,
        )
    except requests.exceptions.Timeout:
        return render_template(
            "index.html",
            error=(
                f"'{hostname}' took too long to respond (timeout: 12 s). "
                "The server may be down, overloaded, or rate-limiting the request."
            ),
            prefill=raw_url,
        )
    except requests.exceptions.TooManyRedirects:
        return render_template(
            "index.html",
            error=(
                f"'{hostname}' returned too many redirects (more than 10 hops). "
                "The site may have a redirect loop."
            ),
            prefill=raw_url,
        )
    except requests.exceptions.RequestException as e:
        return render_template(
            "index.html",
            error=f"Request failed: {str(e)[:200]}",
            prefill=raw_url,
        )

    # ── Step 4: SSRF — validate the *final* URL after redirect chain ─────────
    # Catches open-redirect-to-internal attacks (e.g. example.com → 192.168.1.1)
    final_parsed = urlparse(final_url)
    if final_parsed.hostname and final_parsed.hostname != hostname:
        is_safe_final, ssrf_reason_final = validate_ssrf(final_url)
        if not is_safe_final:
            return render_template(
                "index.html",
                error=(
                    f"The scan was blocked. After following redirects, the request "
                    f"was directed to an internal address. {ssrf_reason_final}"
                ),
                prefill=raw_url,
            )

    # ── Run checks ──────────────────────────────────────────────────────────
    checks = []
    score  = 100

    # Check 0 (implicit): HTTPS / HTTP redirect
    https_check = check_https_redirect(url)
    if https_check:
        checks.append(https_check)
        score -= https_check["deducted"]

    # Check 1: Security headers
    c1 = check_security_headers(dict(response.headers))
    checks.append(c1)
    score -= c1["deducted"]

    # Check 2: SSL certificate (only meaningful for HTTPS final URLs)
    final_parsed = urlparse(final_url)
    if final_parsed.scheme == "https":
        c2 = check_ssl(final_parsed.hostname)
    else:
        c2 = {
            "name": "SSL/TLS Certificate",
            "passed": False,
            "deducted": 0,   # already penalised by HTTPS check above
            "explanation": "SSL check skipped because the site does not use HTTPS.",
        }
    checks.append(c2)
    score -= c2["deducted"]

    # Check 3: Cookies
    c3 = check_cookies(response)
    checks.append(c3)
    score -= c3["deducted"]

    # Check 4: Server leakage
    c4 = check_server_leakage(dict(response.headers))
    checks.append(c4)
    score -= c4["deducted"]

    # Check 5: Sensitive files
    c5 = check_sensitive_files(final_url)
    checks.append(c5)
    score -= c5["deducted"]

    score = max(0, score)
    grade = score_to_grade(score)

    return render_template(
        "results.html",
        url=raw_url,
        final_url=final_url,
        score=score,
        grade=grade,
        checks=checks,
    )

# Vercel imports `app` directly — no __main__ guard needed.
# For local development, run app.py instead.

