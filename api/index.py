import os
import re
import ssl
import time
import json
import base64
import socket
import datetime
from email.utils import parsedate_to_datetime
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse
from html.parser import HTMLParser

try:
    import dns.resolver
except ImportError:
    dns = None

from collections import defaultdict
from threading import Lock

import requests
from flask import Flask, render_template, request, jsonify, redirect, make_response, g, session, url_for
from OpenSSL import crypto

import sys

# Resolve paths relative to this file so Vercel can find templates
# and imported helper modules regardless of invocation directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..")) if os.path.basename(_HERE) == "api" else _HERE
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_TEMPLATES = os.path.join(_ROOT, "templates")
_PUBLIC = os.path.join(_ROOT, "public")

# Load .env in local dev (no-op in Vercel production where vars are injected natively)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(_ROOT, ".env"))
except ImportError:
    pass

from db import (
    get_db_connection, init_db,
    save_scan, get_user_scans, get_scan_by_id, delete_scan,
)
from auth import (
    hash_password, check_password,
    create_user, get_user_by_email, get_user_by_id,
    generate_csrf_token, validate_csrf_token,
)

# static_folder='public' + static_url_path='' mirrors Vercel's CDN behaviour:
# /css/style.css → public/css/style.css in both local dev and production.
app = Flask(__name__, template_folder=_TEMPLATES, static_folder=_PUBLIC, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# ── Session / Cookie Security ─────────────────────────────────────────────────
# httponly prevents JS access to the session cookie.
# samesite=Lax blocks CSRF via cross-origin form POSTs.
# secure=True enforces HTTPS (set automatically to False in local dev via env check).
_is_production = bool(os.environ.get("VERCEL"))  # Vercel sets VERCEL=1 at runtime
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_is_production,  # True in Vercel, False locally
)

# ─────────────────────────────────────────────────────────────────────────────
# In-Memory Sliding-Window Rate Limiter
# ─────────────────────────────────────────────────────────────────────────────

class SlidingWindowRateLimiter:
    """
    Sliding-window in-memory rate limiter per client IP.
    Enforces a strict cap of N requests within a rolling window of W seconds
    (default: 10 scans / 60 s).

    Serverless In-Memory Note:
    In Vercel Serverless Functions, memory is retained across warm container invocations.
    Rapid-fire bursts from an automated client or abusive IP hitting the same warm instance
    are throttled immediately with HTTP 429. If a cold start spawns a new instance, a fresh
    window begins for that container.
    """
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str, cost: int = 1) -> Tuple[bool, int, int]:
        """
        Returns (is_allowed: bool, retry_after_seconds: int, remaining: int).
        Consumes `cost` requests atomically if allowed.
        """
        now = time.time()
        with self._lock:
            # Periodic cleanup if tracking table grows large
            if len(self._requests) > 500:
                expired = [k for k, ts in self._requests.items() if not ts or (now - ts[-1] >= self.window_seconds)]
                for k in expired:
                    del self._requests[k]

            # Purge timestamps outside the sliding window
            timestamps = [t for t in self._requests[key] if now - t < self.window_seconds]
            if len(timestamps) + cost > self.max_requests:
                oldest = timestamps[0] if timestamps else now
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                self._requests[key] = timestamps
                remaining = max(0, self.max_requests - len(timestamps))
                return False, retry_after, remaining

            for _ in range(cost):
                timestamps.append(now)
            self._requests[key] = timestamps
            remaining = max(0, self.max_requests - len(timestamps))
            return True, 0, remaining


scan_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)

# Login-specific rate limiter: 5 failed attempts per IP per 5 minutes.
# Separate from the scan limiter so normal scan usage is never affected.
login_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=300)


def get_client_ip() -> str:
    """
    Extract the client's public IP address from request headers.
    Prioritizes X-Forwarded-For (first entry from Vercel Edge / CDN proxies),
    then X-Real-IP, falling back to remote_addr.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    x_real = request.headers.get("X-Real-IP")
    if x_real:
        ip = x_real.strip()
        if ip:
            return ip
    return request.remote_addr or "127.0.0.1"


# ─────────────────────────────────────────────────────────────────────────────
# Constants & helpers
# ─────────────────────────────────────────────────────────────────────────────

def parse_retry_after(header_val: Optional[str]) -> Optional[int]:
    """
    Parse a Retry-After header value into an integer number of seconds.
    The header may be either:
      - An integer number of seconds (e.g. '120')
      - An HTTP-date (e.g. 'Fri, 31 Dec 2026 23:59:59 GMT')
    Returns seconds >= 0, or None if unparseable / missing.
    """
    if not header_val:
        return None
    header_val = header_val.strip()
    if header_val.isdigit():
        return max(0, int(header_val))
    try:
        dt = parsedate_to_datetime(header_val)
        now = datetime.datetime.now(datetime.timezone.utc)
        diff = int((dt - now).total_seconds())
        return max(0, diff)
    except Exception:
        return None


DEFAULT_COOLDOWN_SECONDS = 120  # 2 minutes default estimate when no Retry-After header is provided

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "points": 5,
        "description": "Restricts sources for executable scripts, styles, and media. Prevents Cross-Site Scripting (XSS) and data injection.",
    },
    "Strict-Transport-Security": {
        "points": 4,
        "description": "Enforces HTTPS connections and disables cleartext fallback. Stops SSL-Stripping and cookie hijacking.",
    },
    "X-Frame-Options": {
        "points": 2,
        "description": "Prevents page embedding within iframes on third-party domains. Defends against UI Redressing (Clickjacking).",
    },
    "X-Content-Type-Options": {
        "points": 2,
        "description": "Blocks MIME-type sniffing. Prevents browsers from interpreting non-executable uploads as executable scripts.",
    },
    "Referrer-Policy": {
        "points": 1,
        "description": "Controls how much URL/referrer data is passed in cross-origin links. Prevents session token and private path leakage.",
    },
    "Permissions-Policy": {
        "points": 1,
        "description": "Restricts browser API access (geolocation, camera, microphone, payment). Reduces attack surface.",
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
        # Handle RFC 6052 Well-Known NAT64 Prefix (64:ff9b::/96)
        # Used by ISPs to reach public IPv4 internet from IPv6 clients.
        if addr.version == 6 and addr in ipaddress.ip_network("64:ff9b::/96"):
            embedded_v4 = ipaddress.IPv4Address(addr.packed[-4:])
            return is_ip_blocked(str(embedded_v4))

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
    raw = re.sub(r"\s+", "", raw or "")
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


class AuditTLSAdapter(requests.adapters.HTTPAdapter):
    """Adapter that permits legacy TLS negotiation down to TLS 1.0 for security auditing."""
    def _create_ssl_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        for cipher_cand in ("DEFAULT@SECLEVEL=0", "ALL:@SECLEVEL=0", "HIGH:MEDIUM:LOW:@SECLEVEL=0", "ALL"):
            try:
                ctx.set_ciphers(cipher_cand)
                break
            except Exception:
                pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._create_ssl_context()
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._create_ssl_context()
        return super().proxy_manager_for(*args, **kwargs)


def safe_get(url: str, timeout: int = 12, allow_redirects: bool = True) -> requests.Response:
    """
    HTTP GET with a shared session, explicit timeout, redirect cap,
    and standard SSL verification with fallback to AuditTLSAdapter so
    sites with certificate/protocol flaws can be audited rather than crashing.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureScan/1.0 (security-audit; github.com/NikhilPoswal/SecureScan)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    }
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    session = requests.Session()
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.max_redirects = 10   # cap redirect chains at 10 hops
    try:
        return session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=True,
        )
    except requests.exceptions.SSLError:
        # Retry with audit TLS adapter so broken certs or legacy TLS sites are audited properly by Check 1 & Check 2
        try:
            fallback_session = requests.Session()
            fallback_session.mount("https://", AuditTLSAdapter())
            fallback_session.mount("http://", requests.adapters.HTTPAdapter(max_retries=0))
            fallback_session.max_redirects = 10
            return fallback_session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
            )
        except requests.exceptions.SSLError:
            mock_resp = requests.Response()
            mock_resp.status_code = 200
            mock_resp.url = url
            mock_resp._content = b""
            mock_resp.headers = requests.structures.CaseInsensitiveDict()
            return mock_resp


def detect_bot_protection(response: requests.Response) -> Optional[dict]:
    """
    Examines HTTP response headers and body to detect if an automated scan was
    blocked by an edge anti-bot challenge (Cloudflare Managed Challenge / Turnstile,
    Akamai Bot Manager, AWS WAF, DataDome, PerimeterX / HUMAN) rather than a
    standard server response or temporary rate limit.
    """
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    server = headers_lower.get("server", "")
    body_sample = (response.text[:5000] if response.text else "").lower()

    # 1. Cloudflare Detection
    cf_mitigated = headers_lower.get("cf-mitigated", "")
    has_cf_ray = "cf-ray" in headers_lower
    is_cf_server = "cloudflare" in server

    # Explicit challenge markers
    if (cf_mitigated == "challenge" or 
        "challenges.cloudflare.com" in body_sample or 
        "challenge-platform" in body_sample or 
        "turnstile" in body_sample or 
        "cf-chl-" in body_sample or
        "just a moment..." in body_sample or
        "attention required! | cloudflare" in body_sample):
        return {
            "provider": "Cloudflare",
            "type": "Managed Challenge / Turnstile",
            "details": "Cloudflare presented an interactive JavaScript / Turnstile challenge page.",
        }

    if is_cf_server or has_cf_ray:
        if "__cf_bm" in response.cookies or cf_mitigated:
            return {
                "provider": "Cloudflare",
                "type": "Cloudflare Bot Management",
                "details": "Cloudflare Bot Management blocked the automated scan.",
            }

    # 2. Akamai Bot Manager
    if ("akamaighost" in server or 
        "x-akamai-transformed" in headers_lower or 
        "ak_bmsc" in response.cookies or 
        "akamai bot manager" in body_sample):
        return {
            "provider": "Akamai",
            "type": "Akamai Bot Manager",
            "details": "Akamai Bot Manager detected and blocked non-browser traffic.",
        }

    # 3. AWS WAF / CloudFront
    if ("x-amz-cf-id" in headers_lower or "cloudfront" in server) and ("aws waf" in body_sample or "request blocked" in body_sample):
        return {
            "provider": "AWS WAF",
            "type": "AWS WAF Challenge / Block",
            "details": "AWS WAF rules intercepted the automated scan request.",
        }

    # 4. DataDome
    if "x-datadome" in headers_lower or "datadome" in response.cookies or "datadome" in body_sample:
        return {
            "provider": "DataDome",
            "type": "DataDome Bot Protection",
            "details": "DataDome anti-bot software blocked the automated request.",
        }

    # 5. PerimeterX / HUMAN
    if "px-captcha" in body_sample or "perimeterx" in body_sample or "_pxhd" in response.cookies:
        return {
            "provider": "HUMAN (PerimeterX)",
            "type": "PerimeterX Bot Challenge",
            "details": "HUMAN (PerimeterX) bot defense presented a challenge page.",
        }

    # 6. Generic JS / Cookie Challenge
    if "enable javascript and cookies to continue" in body_sample or "please turn javascript on and reload the page" in body_sample:
        return {
            "provider": "Anti-Bot WAF",
            "type": "JavaScript / Cookie Challenge",
            "details": "The site requires interactive JavaScript execution to pass security verification.",
        }

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Helper: DNS TXT Resolver with DoH Fallback
# ─────────────────────────────────────────────────────────────────────────────

def query_dns_txt(domain: str) -> list:
    """
    Query DNS TXT records for a domain using dnspython,
    falling back to Google and Cloudflare DNS-over-HTTPS (DoH).
    """
    records = []
    if dns:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
                records.append(txt)
            if records:
                return records
        except Exception:
            pass

    # Fallback to Google DoH
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=TXT", timeout=4)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                if "data" in ans:
                    records.append(ans["data"].strip('"'))
            if records:
                return records
    except Exception:
        pass

    # Fallback to Cloudflare DoH
    try:
        r = requests.get(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
            headers={"Accept": "application/dns-json"},
            timeout=4,
        )
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                if "data" in ans:
                    records.append(ans["data"].strip('"'))
    except Exception:
        pass

    return records


# ─────────────────────────────────────────────────────────────────────────────
# Helper: HTML Mixed Content Parser
# ─────────────────────────────────────────────────────────────────────────────

class MixedContentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = []
        self.passive = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): v for k, v in attrs if v is not None}
        if tag in ("script", "iframe", "embed", "object"):
            src = attrs_dict.get("src") or attrs_dict.get("data", "")
            if src.strip().lower().startswith("http://"):
                self.active.append({"tag": tag, "url": src.strip()})
        elif tag == "link":
            rel = attrs_dict.get("rel", "").lower()
            href = attrs_dict.get("href", "").strip()
            if href.lower().startswith("http://") and any(r in rel for r in ("stylesheet", "import", "preload")):
                self.active.append({"tag": f"link[rel='{rel}']", "url": href})
        elif tag in ("img", "audio", "video", "source"):
            src = attrs_dict.get("src", "").strip()
            if src.lower().startswith("http://"):
                self.passive.append({"tag": tag, "url": src})


def extract_mixed_content(html: str) -> Tuple[list, list]:
    parser = MixedContentParser()
    try:
        parser.feed(html[:500000])  # cap at 500KB to prevent hanging
        return parser.active, parser.passive
    except Exception:
        active = []
        passive = []
        for m in re.finditer(r'<(script|iframe|embed|object)[^>]+(?:src|data)=["\'](http://[^"\']+)["\']', html, re.I):
            active.append({"tag": m.group(1), "url": m.group(2)})
        for m in re.finditer(r'<link[^>]+href=["\'](http://[^"\']+)["\'][^>]*rel=["\'](stylesheet|import|preload)["\']', html, re.I):
            active.append({"tag": f"link[rel='{m.group(2)}']", "url": m.group(1)})
        for m in re.finditer(r'<(img|audio|video|source)[^>]+src=["\'](http://[^"\']+)["\']', html, re.I):
            passive.append({"tag": m.group(1), "url": m.group(2)})
        return active, passive


# ─────────────────────────────────────────────────────────────────────────────
# The 10 Checks
# ─────────────────────────────────────────────────────────────────────────────

def check_ssl(hostname: str, port: int = 443) -> dict:
    """Check 1 – SSL/TLS Certificate Validity & CA Trust"""
    try:
        context = ssl.create_default_context()
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1
        for cipher_cand in ("DEFAULT@SECLEVEL=0", "ALL:@SECLEVEL=0", "ALL"):
            try:
                context.set_ciphers(cipher_cand)
                break
            except Exception:
                pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            context.options |= ssl.OP_LEGACY_SERVER_CONNECT
        conn = context.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
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
            deducted = 20
            explanation = (
                f"Certificate expired on {not_after.date()} ({abs(days_left)} days ago). "
                "Attack Scenario (Man-in-the-Middle & Impersonation): An expired certificate invalidates "
                "the chain of trust. Browsers show full-screen security warnings, and active network attackers "
                "can intercept or spoof connections without detection."
            )
        elif not_yet:
            passed   = False
            deducted = 15
            explanation = (
                f"Certificate is not yet valid (valid starting {not_before.date()}). "
                "Attack Scenario (Handshake Rejection): System clock mismatches or premature certificates cause "
                "browsers to reject the TLS handshake, cutting off secure access."
            )
        elif expires_soon:
            passed   = True
            deducted = 5
            explanation = (
                f"Certificate is valid but expires in {days_left} day(s) on {not_after.date()}. "
                "Risk Scenario (Service Disruption): Once expired, browser block screens will immediately prevent "
                "users from reaching the site. Immediate renewal is recommended."
            )
        else:
            passed   = True
            deducted = 0
            explanation = (
                f"Certificate is valid and trusted (expires {not_after.date()}, {days_left} days left). "
                f"Issued by '{issuer_name}' for '{common_name}'. Identity verified by standard root CAs."
            )

        cert_data = {
            "subject": common_name,
            "common_name": common_name,
            "issuer": issuer_name,
            "expiry": str(not_after.date()),
            "expires": str(not_after.date()),
            "days_left": days_left,
        }

        return {
            "name": "SSL/TLS Certificate Validity",
            "category": "Encryption & Transport",
            "passed": passed,
            "deducted": deducted,
            "explanation": explanation,
            "details": cert_data,
            "cert_info": cert_data,
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "name": "SSL/TLS Certificate Validity",
            "category": "Encryption & Transport",
            "passed": False,
            "deducted": 20,
            "explanation": (
                f"Certificate verification failed ({e.reason}). "
                "Attack Scenario (Active Interception / Untrusted CA): The server's certificate is self-signed, "
                "untrusted, or does not match the domain. An attacker on the local network could be actively "
                "impersonating the server to intercept passwords and cookies."
            ),
        }
    except (ConnectionRefusedError, socket.timeout, OSError):
        return {
            "name": "SSL/TLS Certificate Validity",
            "category": "Encryption & Transport",
            "passed": False,
            "deducted": 15,
            "explanation": (
                "Could not establish a TLS handshake on port 443. "
                "The server may not support HTTPS or blocked the connection. Cleartext HTTP exposes all user data "
                "to local network eavesdropping."
            ),
        }
    except Exception as e:
        return {
            "name": "SSL/TLS Certificate Validity",
            "category": "Encryption & Transport",
            "passed": False,
            "deducted": 10,
            "explanation": f"Unexpected certificate verification error: {str(e)[:140]}",
        }


def check_tls_ciphers(hostname: str, port: int = 443) -> dict:
    """Check 2 – TLS Protocol & Cipher Strength"""
    modern_version = None
    cipher_name = None
    bits = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                modern_version = ssock.version()
                cipher_name, proto, bits = ssock.cipher()
    except Exception:
        pass

    supports_legacy = False
    legacy_version = None
    try:
        legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy_ctx.check_hostname = False
        legacy_ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            legacy_ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            legacy_ctx.minimum_version = ssl.TLSVersion.TLSv1
        for cipher_cand in ("DEFAULT@SECLEVEL=0", "ALL:@SECLEVEL=0", "ALL"):
            try:
                legacy_ctx.set_ciphers(cipher_cand)
                break
            except Exception:
                pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            legacy_ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with legacy_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                supports_legacy = True
                legacy_version = ssock.version()
                if not cipher_name:
                    cipher_name, proto, bits = ssock.cipher()
    except Exception:
        supports_legacy = False

    if not modern_version and legacy_version:
        modern_version = legacy_version

    is_weak_cipher = False
    weak_reasons = []
    if bits is not None and bits < 128:
        is_weak_cipher = True
        weak_reasons.append(f"insufficient key length ({bits}-bit < 128-bit)")
    if cipher_name:
        c_lower = cipher_name.lower()
        if any(w in c_lower for w in ("rc4", "3des", "des", "null", "export", "anon")):
            is_weak_cipher = True
            weak_reasons.append(f"insecure cipher algorithm ({cipher_name})")

    deducted = 0
    passed = True
    reasons = []

    if supports_legacy:
        passed = False
        deducted += 10
        reasons.append(f"Server accepts obsolete protocol handshakes ({legacy_version or 'TLS 1.0/1.1'})")
    if is_weak_cipher:
        passed = False
        deducted += 10
        reasons.append(f"Weak cipher suite detected: {', '.join(weak_reasons)}")

    deducted = min(15, deducted)

    if not passed:
        explanation = (
            f"TLS configuration weakness: {'; '.join(reasons)}. "
            "Attack Scenario (Protocol Downgrade & Traffic Decryption): Outdated protocols allow Man-in-the-Middle "
            "adversaries to force downgrade attacks (e.g. POODLE, BEAST). Weak ciphers allow attackers with recorded "
            "network traffic to mathematically decrypt sessions via Sweet32 or known-plaintext attacks, exposing "
            "passwords and sensitive tokens."
        )
    else:
        explanation = (
            f"Server enforces modern {modern_version or 'TLS 1.2+'} with strong encryption ({cipher_name or 'AES-GCM'}, {bits or 128}-bit). "
            "Deprecated TLS 1.0/1.1 handshakes are rejected, providing strong forward secrecy and immunity to protocol downgrade exploits."
        )

    return {
        "name": "TLS Protocol & Cipher Strength",
        "category": "Encryption & Protocols",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "tls_details": {
            "version": modern_version or legacy_version or "Unknown",
            "modern_version": modern_version or legacy_version or "Unknown",
            "cipher_name": cipher_name or "Unknown",
            "cipher": cipher_name or "Unknown",
            "cipher_bits": bits or 0,
            "bits": bits or 0,
            "legacy_allowed": supports_legacy,
            "supports_legacy": supports_legacy,
            "legacy_version": legacy_version,
        },
    }


def check_security_headers(response_headers: dict) -> dict:
    """Check 3 – HTTP Security Headers"""
    present  = []
    missing  = []
    deducted = 0

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in {k.lower() for k in response_headers}:
            present.append(header)
        else:
            missing.append(header)
            deducted += meta["points"]

    passed = len(missing) == 0
    deducted = min(15, deducted)

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
            f"Missing {len(missing)} of {len(SECURITY_HEADERS)} security headers: {', '.join(missing)}. "
            "Attack Scenario: Missing Content-Security-Policy allows Cross-Site Scripting (XSS) to execute arbitrary "
            "payloads; missing HSTS allows SSL-stripping on public Wi-Fi; missing X-Frame-Options enables Clickjacking "
            "via transparent iframes; missing X-Content-Type-Options allows MIME-sniffing drive-by downloads."
        )
    else:
        explanation = (
            "All 6 major security headers are active and correctly configured. "
            "The browser enforces strict origin isolation, stopping XSS injection, iframe clickjacking, "
            "and MIME-type sniffing."
        )

    return {
        "name": "HTTP Security Headers",
        "category": "Application Defenses",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "detail_rows": detail_rows,
    }


def check_cors(url: str) -> dict:
    """Check 4 – CORS Misconfiguration"""
    test_origin = "https://evil-attacker.example"
    headers = {
        "Origin": test_origin,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureScan/1.0",
    }
    acao = None
    acac = "false"
    try:
        resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac_val = resp.headers.get("Access-Control-Allow-Credentials", "")
        acac = acac_val.strip().lower()
    except Exception:
        pass

    passed = True
    deducted = 0
    is_dangerous = False

    if acao:
        origin_clean = acao.strip()
        credentials_allowed = (acac == "true")

        # Flag genuinely dangerous combo: origin reflected or wildcard + credentials
        if credentials_allowed and (origin_clean == "*" or origin_clean == test_origin or origin_clean == "null"):
            passed = False
            deducted = 10
            is_dangerous = True
            explanation = (
                f"Critical CORS misconfiguration: Server returns 'Access-Control-Allow-Origin: {origin_clean}' "
                "with 'Access-Control-Allow-Credentials: true'. Attack Scenario (Cross-Origin Authenticated Data Theft): "
                "When an authenticated user visits any malicious website, that website's JavaScript can make authenticated "
                "requests to this site in the background and read sensitive private data, user profiles, or API responses, "
                "completely circumventing the Same-Origin Policy (SOP)."
            )
        elif origin_clean == test_origin and not credentials_allowed:
            passed = False
            deducted = 4
            explanation = (
                f"Server dynamically reflects arbitrary origins ('Access-Control-Allow-Origin: {test_origin}') "
                "without credentials. Attack Scenario: While credentials are not sent, unauthenticated internal content, "
                "API structures, or intranet resources can still be scraped cross-origin by arbitrary third-party websites."
            )
        elif origin_clean == "*":
            passed = True
            deducted = 0
            explanation = (
                "Server allows public cross-origin reads ('Access-Control-Allow-Origin: *') without credentials. "
                "This is standard for public APIs and CDN assets and poses no risk to authenticated user sessions."
            )
        else:
            passed = True
            deducted = 0
            explanation = f"CORS policy allows specific trusted origin ({origin_clean}) without arbitrary reflection."
    else:
        passed = True
        deducted = 0
        explanation = (
            "No permissive CORS headers detected. Browsers enforce the strict default Same-Origin Policy (SOP), "
            "blocking any external domain from reading server responses."
        )

    return {
        "name": "CORS Misconfiguration",
        "category": "Cross-Origin Security",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "cors_details": {
            "tested_origin": test_origin,
            "allow_origin": acao or "None",
            "allow_credentials": acac,
            "is_dangerous": is_dangerous,
        },
    }


def check_cookies(response: requests.Response) -> dict:
    """Check 5 – Cookie Security Flags"""
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not set_cookie_headers:
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

    if not set_cookie_headers:
        return {
            "name": "Cookie Security Flags",
            "category": "Session & Identity",
            "passed": True,
            "deducted": 0,
            "explanation": "No cookies set by the server in this response. Session tracking is not exposing client-side state.",
        }

    issues = []
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
            pts += 3
        if not has_httponly:
            cookie_issues.append("missing HttpOnly flag")
            pts += 3
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

    deducted = min(10, deducted)
    passed = len(issues) == 0

    if not passed:
        explanation = (
            f"Insecure cookie flags detected on {len(cookie_details)} cookie(s): {', '.join(issues[:3])}. "
            "Attack Scenario (Session Hijacking & CSRF): Missing HttpOnly allows XSS scripts to access document.cookie "
            "and steal active session tokens; missing Secure allows network sniffers to capture cookies in cleartext; "
            "missing SameSite allows attackers to forge cross-site state-changing requests (CSRF)."
        )
    else:
        explanation = (
            f"All {len(cookie_details)} cookie(s) enforce Secure, HttpOnly, and SameSite attributes. "
            "Session tokens are protected from JavaScript XSS extraction, network eavesdropping, and CSRF attacks."
        )

    return {
        "name": "Cookie Security Flags",
        "category": "Session & Identity",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "cookie_details": cookie_details,
    }


def check_mixed_content(html: str, base_url: str) -> dict:
    """Check 6 – Mixed Content Detection"""
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        return {
            "name": "Mixed Content Detection",
            "category": "Content Integrity",
            "passed": True,
            "deducted": 0,
            "explanation": "Mixed content audit applies only to HTTPS sites.",
            "mixed_details": {"active_count": 0, "passive_count": 0, "resources": []},
        }

    active, passive = extract_mixed_content(html or "")
    total_active = len(active)
    total_passive = len(passive)
    total_issues = total_active + total_passive

    passed = (total_issues == 0)
    deducted = 0
    if total_active > 0:
        deducted = 10
        explanation = (
            f"Detected {total_active} active mixed content resource(s) loaded over insecure HTTP (e.g. {active[0]['url']}). "
            "Attack Scenario (Network Code Injection & Session Takeover): Active mixed content (scripts, stylesheets, iframes) "
            "loaded over plain HTTP can be intercepted and rewritten by a Man-in-the-Middle network attacker (e.g. public Wi-Fi, ISP). "
            "The attacker's modified script runs with full privileges in the user's secure HTTPS session, capturing keystrokes and credentials."
        )
    elif total_passive > 0:
        deducted = 4
        explanation = (
            f"Detected {total_passive} passive mixed content item(s) (images/media) loaded over plain HTTP (e.g. {passive[0]['url']}). "
            "Attack Scenario (Content Defacement & Traffic Snooping): Cleartext media can be altered or monitored by network adversaries, "
            "misleading users or defacing the interface, though script execution is blocked by modern browsers."
        )
    else:
        explanation = (
            "No unencrypted HTTP sub-resources detected. All scripts, stylesheets, iframes, and media assets "
            "are served securely over HTTPS, preserving complete transport integrity."
        )

    all_resources = active[:5] + passive[:max(0, 5 - len(active[:5]))]
    return {
        "name": "Mixed Content Detection",
        "category": "Content Integrity",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "mixed_details": {
            "active_count": total_active,
            "passive_count": total_passive,
            "resources": all_resources,
        },
    }


def check_http_methods(url: str) -> dict:
    """Check 7 – Dangerous HTTP Methods"""
    allow_header = None
    try:
        r_opt = requests.options(url, headers={"User-Agent": "SecureScan/1.0"}, timeout=6, allow_redirects=True)
        allow_header = r_opt.headers.get("Allow") or r_opt.headers.get("Public")
    except Exception:
        pass

    trace_active = False
    try:
        r_trace = requests.request("TRACE", url, headers={"User-Agent": "SecureScan/1.0", "X-SecureScan-Probe": "XSTTest"}, timeout=5)
        if r_trace.status_code == 200 and ("X-SecureScan-Probe" in r_trace.text or "XSTTest" in r_trace.text):
            trace_active = True
    except Exception:
        pass

    methods_list = [m.strip().upper() for m in allow_header.split(",")] if allow_header else []
    dangerous_methods = [m for m in methods_list if m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT")]

    passed = True
    deducted = 0
    if trace_active or "TRACE" in methods_list or "TRACK" in methods_list:
        passed = False
        deducted = 5
        explanation = (
            "HTTP TRACE / TRACK method is actively enabled on the web server. "
            "Attack Scenario (Cross-Site Tracing / XST): When TRACE is enabled, an attacker who identifies a Cross-Site "
            "Scripting (XSS) flaw can send a TRACE request. The web server reflects the client's HTTP request headers—including "
            "HttpOnly cookies—directly into the response body, completely defeating HttpOnly protections and exposing session cookies."
        )
    elif any(m in ("PUT", "DELETE") for m in dangerous_methods):
        passed = False
        deducted = 3
        explanation = (
            f"Dangerous HTTP modification methods advertised in Allow header: {', '.join(dangerous_methods)}. "
            "Attack Scenario (Unauthorized Resource Tampering): If PUT or DELETE are accessible without strict authentication, "
            "adversaries can overwrite website content, upload malicious web shells, or delete critical web application files."
        )
    else:
        explanation = (
            f"Web server restricts HTTP verbs to standard methods ({allow_header or 'GET, HEAD, POST, OPTIONS'}). "
            "Dangerous debugging methods (TRACE, TRACK) and unauthorized file-write methods (PUT, DELETE) are disabled."
        )

    return {
        "name": "Dangerous HTTP Methods",
        "category": "Server Configuration",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "method_details": {
            "allowed_methods": allow_header or "Not advertised",
            "trace_enabled": trace_active,
            "dangerous_methods": dangerous_methods,
        },
    }


def check_email_security(hostname: str) -> dict:
    """Check 8 – Email Spoofing Defense (SPF & DMARC)"""
    try:
        ipaddress.ip_address(hostname)
        return {
            "name": "Email Spoofing Defense (SPF & DMARC)",
            "category": "Domain & Phishing Defense",
            "passed": True,
            "deducted": 0,
            "explanation": "Target is a raw IP address; email authentication records apply only to domain names.",
            "email_details": {"spf_record": None, "dmarc_record": None, "apex_domain": hostname, "issues": []},
        }
    except ValueError:
        pass

    parts = hostname.split(".")
    candidates = [hostname]
    if len(parts) > 2:
        candidates.append(".".join(parts[-2:]))

    spf_record = None
    for d in candidates:
        txts = query_dns_txt(d)
        for t in txts:
            if t.startswith("v=spf1"):
                spf_record = t
                break
        if spf_record:
            break

    dmarc_record = None
    for d in candidates:
        txts = query_dns_txt(f"_dmarc.{d}")
        for t in txts:
            if t.startswith("v=DMARC1"):
                dmarc_record = t
                break
        if dmarc_record:
            break

    issues = []
    deducted = 0

    if not spf_record:
        issues.append("missing SPF record")
        deducted += 5
    elif "+all" in spf_record.lower():
        issues.append("permissive SPF (+all permits any sender)")
        deducted += 5

    if not dmarc_record:
        issues.append("missing DMARC record")
        deducted += 5
    elif "p=none" in dmarc_record.lower():
        issues.append("DMARC policy is monitoring-only (p=none)")
        deducted += 2

    deducted = min(10, deducted)
    passed = (len(issues) == 0)

    apex = candidates[-1]
    if not passed:
        explanation = (
            f"Email spoofing protections missing: {'; '.join(issues)}. "
            f"Attack Scenario (Phishing, BEC & Domain Impersonation): Because the domain lacks strict SPF and DMARC enforcement, "
            f"attackers anywhere on the internet can send emails forged to appear as 'From: support@{apex}' or 'ceo@{apex}'. "
            "Mail servers will deliver the spoofed emails directly to user inboxes, facilitating Business Email Compromise (BEC) "
            "and credential phishing under your trusted brand."
        )
    else:
        explanation = (
            f"Strict email spoofing defenses verified. Domain publishes valid SPF ({spf_record[:35]}...) and "
            f"enforcing DMARC policy ({dmarc_record[:35]}...). Inbound mail servers will reject or quarantine "
            "forged sender addresses, stopping executive impersonation and phishing."
        )

    return {
        "name": "Email Spoofing Defense (SPF & DMARC)",
        "category": "Domain & Phishing Defense",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "email_details": {
            "spf_record": spf_record or "None",
            "dmarc_record": dmarc_record or "None",
            "apex_domain": apex,
            "issues": issues,
        },
    }


def check_sensitive_files(base_url: str) -> dict:
    """Check 9 – Exposed Sensitive Files"""
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    session = requests.Session()
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureScan/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    exposed = []
    for i, path in enumerate(SENSITIVE_PATHS):
        if i > 0:
            time.sleep(0.30)  # polite 300ms spacing
        try:
            resp = session.get(
                base + path,
                timeout=5,
                allow_redirects=False,
                verify=False,
                headers=headers,
            )
            if resp.status_code == 200 and len(resp.content) > 0:
                exposed.append(path)
        except Exception:
            continue

    if exposed:
        deducted = min(len(exposed) * 5, 10)
        passed   = False
        explanation = (
            f"Publicly accessible sensitive file(s) found: {', '.join(exposed)}. "
            "Attack Scenario (Credential Harvesting & Source Reconstruction): Directly readable .env or .git repositories "
            "expose database credentials, secret API tokens, and complete application source code. Attackers use automated "
            "dumpers to reconstruct the codebase and extract private infrastructure secrets without triggering alarms."
        )
    else:
        deducted = 0
        passed   = True
        explanation = (
            "No sensitive deployment or configuration files (.env, .git/config, .htaccess, web.config) are publicly accessible. "
            "Web server access controls properly restrict sensitive directory indexing."
        )

    return {
        "name": "Sensitive File Exposure",
        "category": "Access Control & Configuration",
        "passed": passed,
        "deducted": deducted,
        "explanation": explanation,
        "exposed_paths": exposed,
    }


def check_server_leakage(response_headers: dict) -> dict:
    """Check 10 – Server Technology Fingerprinting"""
    leaky_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Generator", "X-Runtime"]

    found_leaks = {}
    for h in leaky_headers:
        for k, v in response_headers.items():
            if k.lower() == h.lower() and v.strip():
                found_leaks[k] = v

    version_pattern = re.compile(r"\d+[\.\d]*")
    reveals_version = any(version_pattern.search(v) for v in found_leaks.values())

    if not found_leaks:
        return {
            "name": "Server Technology Fingerprinting",
            "category": "Information Disclosure",
            "passed": True,
            "deducted": 0,
            "explanation": (
                "Server software and technology headers are suppressed or obfuscated. "
                "Attackers cannot easily fingerprint backend server software or frameworks during reconnaissance."
            ),
        }
    elif reveals_version:
        explanation = (
            f"Server response headers disclose exact software and release versions: {', '.join(f'{k}: {v}' for k, v in found_leaks.items())}. "
            "Attack Scenario (Targeted CVE Exploitation): Broadcasting exact software versions allows adversaries to search "
            "vulnerability databases (NVD/CVE) for unpatched flaws matching that specific release, enabling targeted exploits."
        )
        return {
            "name": "Server Technology Fingerprinting",
            "category": "Information Disclosure",
            "passed": False,
            "deducted": 5,
            "explanation": explanation,
            "leaks": found_leaks,
        }
    else:
        explanation = (
            f"Server technology identity is disclosed ({', '.join(f'{k}: {v}' for k, v in found_leaks.items())}) "
            "without exact version numbers. Attack Scenario: Discloses infrastructure vendor to attackers during reconnaissance. "
            "Suppressing these headers further hardens the perimeter."
        )
        return {
            "name": "Server Technology Fingerprinting",
            "category": "Information Disclosure",
            "passed": False,
            "deducted": 2,
            "explanation": explanation,
            "leaks": found_leaks,
        }


def check_https_redirect(url: str) -> Optional[dict]:
    """
    If the user supplied an HTTPS URL but the plain HTTP version redirects to HTTPS,
    returns None (no penalty). If the site is HTTP-only, returns a penalty dict.
    """
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return None

    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
    try:
        resp = requests.get(http_url, timeout=8, allow_redirects=False,
                            headers={"User-Agent": "SecureScan/1.0"})
        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
            return None
    except Exception:
        pass

    return {
        "name": "HTTPS / Cleartext Transmission",
        "category": "Encryption & Transport",
        "passed": False,
        "deducted": 20,
        "explanation": (
            "The site is served over unencrypted HTTP and does not automatically redirect to HTTPS. "
            "Attack Scenario (Cleartext Sniffing & Session Hijacking): All communication—including passwords, "
            "session tokens, and personal details—is transmitted in plaintext. Anyone on the local network path "
            "can passively sniff credentials or tamper with page content."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
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
    if hasattr(g, "rate_limit_remaining"):
        response.headers["X-RateLimit-Limit"] = str(g.rate_limit_limit)
        response.headers["X-RateLimit-Remaining"] = str(g.rate_limit_remaining)
    return response


@app.route("/")
def index():
    """Homepage. Initialises DB schema on first cold start if DATABASE_URL is set."""
    try:
        init_db()
    except Exception:
        pass  # DB not configured — anonymous scan flow continues unaffected
    return render_template("index.html")


@app.route("/notes")
@app.route("/about")
def notes():
    return render_template("notes.html")


@app.route("/export-pdf", methods=["GET", "POST"])
def export_pdf():
    """
    Exports a professional, print-ready PDF security audit report.
    Accepts POST with base64-encoded JSON report_data, generates PDF via ReportLab,
    and serves it as a downloadable attachment.
    """
    from report_generator import generate_pdf_report

    if request.method == "POST":
        b64_data = request.form.get("report_data", "")
        if b64_data:
            try:
                raw_json = base64.b64decode(b64_data.encode("ascii")).decode("utf-8")
                data = json.loads(raw_json)
                pdf_bytes = generate_pdf_report(data)
                hostname = urlparse(data.get("url", "")).hostname or urlparse(data.get("final_url", "")).hostname or "site"
                safe_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", hostname)
                filename = f"securescan_{safe_host}_report.pdf"

                resp = make_response(pdf_bytes)
                resp.headers["Content-Type"] = "application/pdf"
                resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
                return resp
            except Exception as e:
                return f"PDF generation error: {str(e)}", 400

    raw_url = request.args.get("url", "")
    if raw_url:
        return redirect(f"/scan?url={raw_url}")

    return "No report data provided.", 400


@app.route("/test-pdf")
def test_pdf():
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 700, "SecureScan ReportLab Test PDF — Hello Vercel!")
    c.save()
    pdf_data = buf.getvalue()
    buf.close()

    resp = make_response(pdf_data)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="securescan_test.pdf"'
    return resp


@app.route("/check-status", methods=["GET", "POST"])
def check_status():
    """
    Lightweight, cheap verification check to see if target block has cleared.
    Makes a single HEAD request with SSRF validation. Never runs full scans.
    """
    if request.method == "POST":
        raw_url = request.form.get("url") or (request.json.get("url") if request.is_json else "")
    else:
        raw_url = request.args.get("url", "")

    raw_url = re.sub(r"\s+", "", raw_url or "")
    if not raw_url:
        return jsonify({"error": "Missing URL parameter", "is_clear": False, "is_blocked": False}), 400

    url = normalize_url(raw_url)
    if not url:
        return jsonify({"error": "Invalid URL format", "is_clear": False, "is_blocked": False}), 400

    # SSRF protection
    is_safe, ssrf_reason = validate_ssrf(url)
    if not is_safe:
        return jsonify({"error": ssrf_reason, "is_clear": False, "is_blocked": False}), 400

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureScan/1.0 (security-audit; github.com/NikhilPoswal/SecureScan)",
        "Accept": "*/*",
    }

    try:
        # 1. Try cheap HEAD request first
        resp = requests.head(url, timeout=6, allow_redirects=True, headers=headers)
        # If HEAD returns 405 Method Not Allowed, fallback to GET headers only
        if resp.status_code == 405:
            resp = requests.get(url, timeout=6, stream=True, allow_redirects=True, headers=headers)
            resp.close()

        status_code = resp.status_code
        is_clear = (200 <= status_code < 400)
        is_blocked = (status_code in (403, 429))
        retry_header = resp.headers.get("Retry-After")

        return jsonify({
            "status": status_code,
            "is_clear": is_clear,
            "is_blocked": is_blocked,
            "retry_after": retry_header or None,
            "target_url": url,
        })
    except requests.exceptions.SSLError as e:
        return jsonify({"status": 526, "is_clear": False, "is_blocked": False, "error": f"SSL Error: {str(e)[:100]}"})
    except requests.exceptions.Timeout:
        return jsonify({"status": 504, "is_clear": False, "is_blocked": False, "error": "Connection timed out"})
    except requests.exceptions.RequestException as e:
        return jsonify({"status": 500, "is_clear": False, "is_blocked": False, "error": str(e)[:120]})


def handle_rate_limited(raw_url: str, retry_after: int, client_ip: str):
    """Helper to return an honest, structured HTTP 429 response for single scans."""
    if request.headers.get("Accept") == "application/json" or request.is_json:
        resp = jsonify({
            "error": "Rate limit exceeded",
            "message": (
                f"SecureScan limits scans to {scan_limiter.max_requests} per minute per IP. "
                f"Please wait {retry_after} seconds before scanning again."
            ),
            "retry_after": retry_after,
            "limit": scan_limiter.max_requests,
        })
        resp.status_code = 429
    else:
        limit_msg = (
            f"Rate limit reached: You've initiated {scan_limiter.max_requests} scans in the last minute. "
            f"To protect shared serverless resources and avoid target disruption, please wait {retry_after} seconds before scanning again."
        )
        resp = make_response(
            render_template(
                "index.html",
                error=limit_msg,
                rate_limit_info={
                    "limit": scan_limiter.max_requests,
                    "retry_after": retry_after,
                    "client_ip": client_ip,
                },
                prefill=raw_url,
            ),
            429,
        )
    resp.headers["Retry-After"] = str(retry_after)
    resp.headers["X-RateLimit-Limit"] = str(scan_limiter.max_requests)
    resp.headers["X-RateLimit-Remaining"] = "0"
    resp.headers["X-RateLimit-Reset"] = str(int(time.time() + retry_after))
    return resp


def audit_target(raw_url: str, timeout: int = 12) -> dict:
    """
    Executes a complete 10-point cybersecurity audit for a single URL.
    Returns a dictionary with 'success': True and audit metrics, or 'success': False
    and specific diagnostic details (error message, bot_protection info, or cooldown_info).
    """
    raw_url = re.sub(r"\s+", "", raw_url or "")
    if not raw_url:
        return {
            "success": False,
            "raw_url": "",
            "url": "",
            "error": "Please enter a URL to scan.",
        }

    url = normalize_url(raw_url)
    if url is None:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": raw_url,
            "error": (
                "Invalid URL format. Please enter a public web address "
                "(e.g. github.com or https://example.com). "
                "Only http:// and https:// URLs are supported."
            ),
        }

    parsed = urlparse(url)
    hostname = parsed.hostname

    # Step 2: SSRF check on initial URL
    is_safe, ssrf_reason = validate_ssrf(url)
    if not is_safe:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": url,
            "error": ssrf_reason,
        }

    # Step 3: Fetch target page
    try:
        response = safe_get(url, timeout=timeout)
        final_url = response.url
    except requests.exceptions.SSLError as e:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": url,
            "error": (
                f"SSL error when connecting to {hostname}: the certificate may be "
                f"invalid, expired, or self-signed. Detail: {str(e)[:180]}"
            ),
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": url,
            "error": (
                f"Could not connect to '{hostname}'. "
                "The domain may not exist, or the server refused the connection."
            ),
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": url,
            "error": (
                f"'{hostname}' took too long to respond (timeout: {timeout} s). "
                "The server may be down, overloaded, or rate-limiting the request."
            ),
        }
    except requests.exceptions.TooManyRedirects:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": url,
            "error": (
                f"'{hostname}' returned too many redirects (more than 10 hops). "
                "The site may have a redirect loop."
            ),
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": url,
            "error": f"Request failed: {str(e)[:200]}",
        }

    # Step 4: SSRF check on final URL
    final_parsed = urlparse(final_url)
    if final_parsed.hostname and final_parsed.hostname != hostname:
        is_safe_final, ssrf_reason_final = validate_ssrf(final_url)
        if not is_safe_final:
            return {
                "success": False,
                "raw_url": raw_url,
                "url": final_url,
                "error": (
                    f"The scan was blocked. After following redirects, the request "
                    f"was directed to an internal address. {ssrf_reason_final}"
                ),
            }

    # Step 4b: Validate HTTP response status
    status = response.status_code
    if status in (403, 429):
        bot_info = detect_bot_protection(response)
        if bot_info:
            return {
                "success": False,
                "raw_url": raw_url,
                "url": final_url,
                "bot_protection": bot_info,
                "error": f"Automated audit blocked by {bot_info.get('provider', 'anti-bot protection')}.",
            }

    if status == 429:
        retry_header = response.headers.get("Retry-After")
        parsed_retry = parse_retry_after(retry_header)
        is_exact = (parsed_retry is not None and parsed_retry > 0)
        cooldown_info = {
            "is_exact": is_exact,
            "target_url": url,
            "raw_retry_after": retry_header or "",
            "status_code": 429,
        }
        return {
            "success": False,
            "raw_url": raw_url,
            "url": final_url,
            "cooldown_info": cooldown_info,
            "error": (
                "This site rate-limited our scan (HTTP 429 Too Many Requests). "
                "Web application firewalls or rate limiters often restrict automated security audits."
            ),
        }

    if status == 403:
        retry_header = response.headers.get("Retry-After")
        parsed_retry = parse_retry_after(retry_header)
        is_exact = (parsed_retry is not None and parsed_retry > 0)

        server = response.headers.get("Server", "")
        v_err = response.headers.get("X-Vercel-Error", "")
        v_id = response.headers.get("X-Vercel-Id", "")
        body_snip = response.text[:120].strip().replace("\n", " ")
        diag = []
        if server: diag.append(f"Server: {server}")
        if v_err: diag.append(f"X-Vercel-Error: {v_err}")
        if v_id: diag.append(f"X-Vercel-Id: {v_id}")
        if body_snip: diag.append(f"Body: {body_snip}")
        diag_str = f" ({'; '.join(diag)})" if diag else ""

        cooldown_info = {
            "is_exact": is_exact,
            "target_url": url,
            "raw_retry_after": retry_header or "",
            "status_code": 403,
        }
        return {
            "success": False,
            "raw_url": raw_url,
            "url": final_url,
            "cooldown_info": cooldown_info,
            "error": f"Access was blocked by the target site (HTTP 403 Forbidden).{diag_str}",
        }

    if status >= 400:
        return {
            "success": False,
            "raw_url": raw_url,
            "url": final_url,
            "error": (
                f"The target server returned an error (HTTP {status}). "
                "Could not audit security posture because the site did not return a successful response."
            ),
        }

    # Step 5: Run all 10 checks
    checks = []

    https_check = check_https_redirect(url)
    if https_check:
        checks.append(https_check)

    final_parsed = urlparse(final_url)
    is_https = (final_parsed.scheme == "https")
    host = final_parsed.hostname or ""
    port = final_parsed.port or (443 if is_https else 80)

    # Check 1: SSL Certificate Validity
    if is_https:
        c1 = check_ssl(host, port)
    else:
        c1 = {
            "name": "SSL/TLS Certificate Validity",
            "category": "Encryption & Transport",
            "passed": False,
            "deducted": 0,
            "explanation": "SSL certificate check skipped because the site is served over unencrypted HTTP.",
        }
    checks.append(c1)

    # Check 2: TLS Protocol & Cipher Strength
    if is_https:
        c2 = check_tls_ciphers(host, port)
    else:
        c2 = {
            "name": "TLS Protocol & Cipher Strength",
            "category": "Encryption & Protocols",
            "passed": False,
            "deducted": 0,
            "explanation": "TLS cipher strength check skipped because the site is served over unencrypted HTTP.",
        }
    checks.append(c2)

    # Check 3: HTTP Security Headers
    c3 = check_security_headers(dict(response.headers))
    checks.append(c3)

    # Check 4: CORS Misconfiguration
    c4 = check_cors(url)
    checks.append(c4)

    # Check 5: Cookie Security Flags
    c5 = check_cookies(response)
    checks.append(c5)

    # Check 6: Mixed Content Detection
    c6 = check_mixed_content(response.text, final_url)
    checks.append(c6)

    # Check 7: Dangerous HTTP Methods
    c7 = check_http_methods(url)
    checks.append(c7)

    # Check 8: Email Spoofing Defense (SPF & DMARC)
    c8 = check_email_security(host)
    checks.append(c8)

    # Check 9: Sensitive File Exposure
    c9 = check_sensitive_files(final_url)
    checks.append(c9)

    # Check 10: Server Technology Fingerprinting
    c10 = check_server_leakage(dict(response.headers))
    checks.append(c10)

    # Compute overall score and grade
    total_deductions = sum(c["deducted"] for c in checks)
    score = max(0, 100 - total_deductions)
    grade = score_to_grade(score)

    time_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    report_dict = {
        "url": raw_url,
        "final_url": final_url,
        "score": score,
        "grade": grade,
        "timestamp": time_str,
        "checks": [
            {
                "name": c.get("name"),
                "category": c.get("category", "General"),
                "passed": c.get("passed", False),
                "deducted": c.get("deducted", 0),
                "explanation": c.get("explanation", ""),
            }
            for c in checks
        ],
    }
    report_json_b64 = base64.b64encode(json.dumps(report_dict).encode("utf-8")).decode("ascii")

    return {
        "success": True,
        "raw_url": raw_url,
        "url": url,
        "final_url": final_url,
        "score": score,
        "grade": grade,
        "checks": checks,
        "report_dict": report_dict,
        "report_json_b64": report_json_b64,
        "timestamp": time_str,
    }



# ─────────────────────────────────────────────────────────────────────────────
# Flask Request Lifecycle Hooks
# ─────────────────────────────────────────────────────────────────────────────

@app.before_request
def load_logged_in_user():
    """
    Runs before every request.
    If a user_id is in the session (set on login), fetches the user row
    from the DB and stores it in g.current_user so templates can access it.
    If DATABASE_URL is not set (e.g. local dev without DB), silently skips.
    """
    g.current_user = None
    user_id = session.get("user_id")
    if user_id:
        try:
            g.current_user = get_user_by_id(user_id)
        except Exception:
            # DB unavailable or connection error — clear the stale session
            session.clear()
            g.current_user = None


@app.context_processor
def inject_current_user():
    """Make current_user available in all Jinja2 templates as {{ current_user }}."""
    return {"current_user": getattr(g, "current_user", None)}


# ─────────────────────────────────────────────────────────────────────────────
# Authentication Routes (Batch 1)
# ─────────────────────────────────────────────────────────────────────────────


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET:  Render the login form.
    POST: Authenticate the user.
          - CSRF token is validated first.
          - Login attempt rate is limited per IP (5 failures / 5 min).
          - Passwords are verified with constant-time comparison.
          - On success: session is regenerated (cleared + new user_id set).
    """
    # Already logged in → send to home
    if g.current_user:
        return redirect("/")

    if request.method == "GET":
        csrf_token = generate_csrf_token(session)
        return render_template("login.html", csrf_token=csrf_token)

    # POST — validate CSRF first
    form_csrf = request.form.get("_csrf_token")
    if not validate_csrf_token(session, form_csrf):
        return render_template("login.html",
                               csrf_token=generate_csrf_token(session),
                               error="Invalid form submission. Please try again."), 400

    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("login.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Email and password are required.")

    # Check login rate limit (keyed on IP to resist credential-stuffing)
    client_ip = get_client_ip()
    allowed, retry_after, _ = login_limiter.is_allowed(client_ip)
    if not allowed:
        return render_template("login.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error=f"Too many failed login attempts. "
                                     f"Please wait {retry_after} seconds before trying again."), 429

    # Fetch user and verify password
    try:
        user = get_user_by_email(email)
    except Exception:
        return render_template("login.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Database temporarily unavailable. Please try again shortly."), 503

    if user is None or not check_password(password, user["password_hash"]):
        # Intentionally generic message (don't reveal whether the email exists)
        return render_template("login.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Incorrect email or password.")

    # Success: regenerate session (clear old data, set user_id)
    session.clear()
    session["user_id"] = user["id"]
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    GET:  Render the sign-up form.
    POST: Create a new account.
          - Validates email format, password length (≥8), and password match.
          - Parameterized INSERT via auth.create_user() prevents SQLi.
          - On duplicate email: returns a clear error (no info disclosure beyond the email itself).
          - On success: logs the user in immediately (same as post-login flow).
    """
    if g.current_user:
        return redirect("/")

    if request.method == "GET":
        csrf_token = generate_csrf_token(session)
        return render_template("signup.html", csrf_token=csrf_token)

    # POST — validate CSRF first
    form_csrf = request.form.get("_csrf_token")
    if not validate_csrf_token(session, form_csrf):
        return render_template("signup.html",
                               csrf_token=generate_csrf_token(session),
                               error="Invalid form submission. Please try again."), 400

    email     = request.form.get("email", "").strip().lower()
    password  = request.form.get("password", "")
    password2 = request.form.get("password2", "")

    # Server-side validation (client-side is convenience only)
    _EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    if not email or not _EMAIL_RE.match(email):
        return render_template("signup.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Please enter a valid email address.")

    if len(password) < 8:
        return render_template("signup.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Password must be at least 8 characters.")

    if password != password2:
        return render_template("signup.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Passwords do not match.")

    # Initialise DB schema on first-ever signup (idempotent)
    try:
        init_db()
        user = create_user(email, password)
    except ValueError as e:
        # Duplicate email
        return render_template("signup.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error=str(e))
    except Exception:
        return render_template("signup.html",
                               csrf_token=generate_csrf_token(session),
                               prefill_email=email,
                               error="Account creation failed due to a database error. Please try again."), 503

    # Log the new user in immediately
    session.clear()
    session["user_id"] = user["id"]
    return redirect("/")


@app.route("/logout")
def logout():
    """Clear the session and redirect to the homepage."""
    session.clear()
    return redirect("/")


@app.route("/account")
def account():
    """
    Account overview page — shows the logged-in user's email and member-since date.
    Redirects to /login if the user is not authenticated.
    No sensitive operations happen here (read-only); CSRF not required.
    """
    if not g.current_user:
        return redirect("/login")
    return render_template("account.html")


@app.route("/dashboard")
def dashboard():
    """
    Dashboard of saved scans for the authenticated user.
    Redirects to /login if not authenticated.
    Supports pagination: ?page=1 (20 scans per page).
    """
    if not g.current_user:
        return redirect("/login")

    try:
        page = int(request.args.get("page", 1))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = 1

    per_page = 20
    offset = (page - 1) * per_page

    try:
        scans, total = get_user_scans(g.current_user["id"], limit=per_page, offset=offset)
    except Exception as e:
        app.logger.error(f"Failed to load user scans: {e}")
        scans, total = [], 0

    total_pages = max(1, (total + per_page - 1) // per_page)
    csrf_token = generate_csrf_token(session)

    return render_template(
        "dashboard.html",
        scans=scans,
        total=total,
        page=page,
        total_pages=total_pages,
        csrf_token=csrf_token,
    )


@app.route("/dashboard/scan/<int:scan_id>")
def view_saved_scan(scan_id: int):
    """
    View full results of a saved scan.
    Strictly authorized to the logged-in user: returns 404 if not found or belongs to another user.
    Reuses results.html for identical visual presentation.
    """
    if not g.current_user:
        return redirect("/login")

    scan = get_scan_by_id(scan_id, user_id=g.current_user["id"])
    if not scan:
        return render_template("index.html", error="Scan not found or access denied."), 404

    results_data = scan.get("results_json", {})
    checks = results_data.get("checks", [])
    report_json_b64 = results_data.get("report_json_b64") or ""
    if not report_json_b64:
        report_dict = results_data.get("report_dict") or {
            "url": scan["url"],
            "final_url": scan["final_url"],
            "score": scan["score"],
            "grade": scan["grade"],
            "timestamp": scan["created_at"].strftime("%Y-%m-%d %H:%M UTC") if hasattr(scan["created_at"], "strftime") else str(scan["created_at"]),
            "checks": checks,
        }
        report_json_b64 = base64.b64encode(json.dumps(report_dict).encode("utf-8")).decode("ascii")

    return render_template(
        "results.html",
        url=scan["url"],
        final_url=scan["final_url"],
        score=scan["score"],
        grade=scan["grade"],
        checks=checks,
        report_json_b64=report_json_b64,
        is_saved_scan=True,
        saved_scan_id=scan["id"],
    )


@app.route("/dashboard/scan/<int:scan_id>/delete", methods=["POST"])
def delete_saved_scan(scan_id: int):
    """
    Delete a saved scan with CSRF validation.
    Strictly authorized to the logged-in user: returns 404 if scan belongs to another user.
    """
    if not g.current_user:
        return redirect("/login")

    form_csrf = request.form.get("_csrf_token")
    if not validate_csrf_token(session, form_csrf):
        return render_template("dashboard.html",
                               error="Invalid CSRF token for deletion. Please try again.",
                               scans=[], total=0, page=1, total_pages=1,
                               csrf_token=generate_csrf_token(session)), 400

    deleted = delete_scan(scan_id, user_id=g.current_user["id"])
    if not deleted:
        return render_template("index.html", error="Scan not found or access denied."), 404

    return redirect("/dashboard")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        raw_url = request.args.get("url", "")
        if not raw_url.strip():
            return redirect("/")
    else:
        raw_url = request.form.get("url", "")

    raw_url = re.sub(r"\s+", "", raw_url or "")

    # Rate limiting (1 scan token)
    client_ip = get_client_ip()
    allowed, retry_after, remaining = scan_limiter.is_allowed(client_ip, cost=1)
    g.rate_limit_limit = scan_limiter.max_requests
    g.rate_limit_remaining = remaining
    if not allowed:
        return handle_rate_limited(raw_url, retry_after, client_ip)

    if not raw_url:
        return render_template("index.html", error="Please enter a URL to scan.")

    result = audit_target(raw_url, timeout=12)
    if not result["success"]:
        return render_template(
            "index.html",
            error=result.get("error"),
            bot_protection=result.get("bot_protection"),
            cooldown_info=result.get("cooldown_info"),
            prefill=raw_url,
        )

    # Automatically save scan if user is logged in (Batch 2)
    saved_scan_id = None
    if g.current_user:
        try:
            saved_scan_id = save_scan(
                user_id=g.current_user["id"],
                url=result["raw_url"],
                final_url=result["final_url"],
                score=result["score"],
                grade=result["grade"],
                results_data=result,
            )
        except Exception as e:
            app.logger.error(f"Failed to auto-save scan: {e}")

    resp = make_response(
        render_template(
            "results.html",
            url=result["raw_url"],
            final_url=result["final_url"],
            score=result["score"],
            grade=result["grade"],
            checks=result["checks"],
            report_json_b64=result["report_json_b64"],
            saved_scan_id=saved_scan_id,
        )
    )
    resp.headers["X-RateLimit-Limit"] = str(scan_limiter.max_requests)
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    return resp


@app.route("/api/scan", methods=["GET", "POST"])
def api_scan():
    """
    Public REST API endpoint returning structured 10-point cybersecurity audit data as JSON.
    Usage:
        GET /api/scan?url=example.com
        POST /api/scan (form-data: url=example.com, or JSON: {"url": "example.com"})
    """
    if request.method == "GET":
        raw_url = request.args.get("url", "")
    else:
        if request.is_json and request.json:
            raw_url = request.json.get("url", "")
        else:
            raw_url = request.form.get("url", "")

    raw_url = re.sub(r"\s+", "", raw_url or "")
    if not raw_url:
        return jsonify({
            "error": "Missing URL parameter",
            "message": "Please provide a website URL to scan (e.g. /api/scan?url=example.com)",
            "status": 400
        }), 400

    # Rate limiting: 1 token per scan
    client_ip = get_client_ip()
    allowed, retry_after, remaining = scan_limiter.is_allowed(client_ip, cost=1)
    g.rate_limit_limit = scan_limiter.max_requests
    g.rate_limit_remaining = remaining

    if not allowed:
        resp = jsonify({
            "error": "Rate limit exceeded",
            "message": f"SecureScan limits scans to {scan_limiter.max_requests} per minute per IP. Please wait {retry_after} seconds before scanning again.",
            "limit": scan_limiter.max_requests,
            "retry_after": retry_after,
            "status": 429
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = str(scan_limiter.max_requests)
        resp.headers["X-RateLimit-Remaining"] = str(remaining)
        return resp

    # Run the unified audit engine (timeout=12)
    res = audit_target(raw_url, timeout=12)

    if not res["success"]:
        # Case 1: Bot-protection challenge (Cloudflare Turnstile, AWS WAF, etc.)
        if res.get("bot_protection"):
            resp = jsonify({
                "error": "Scan blocked by bot protection",
                "message": res.get("error"),
                "url": raw_url,
                "bot_protection": res.get("bot_protection"),
                "status": 403
            })
            resp.status_code = 403
            return resp

        # Case 2: Target WAF cooldown / rate limit (403/429)
        if res.get("cooldown_info"):
            resp = jsonify({
                "error": "Target WAF rate limit detected",
                "message": res.get("error"),
                "url": raw_url,
                "cooldown_info": res.get("cooldown_info"),
                "status": 429
            })
            resp.status_code = 429
            return resp

        # Case 3: SSRF / Invalid Domain / Connection Error
        err_msg = res.get("error", "Scan failed")
        is_bad_request = (
            "reserved" in err_msg
            or "private" in err_msg
            or "Invalid URL" in err_msg
            or "loopback" in err_msg
            or "SSRF" in err_msg
        )
        status_code = 400 if is_bad_request else 502
        resp = jsonify({
            "error": "Scan failed",
            "message": err_msg,
            "url": raw_url,
            "status": status_code
        })
        resp.status_code = status_code
        return resp

    # Success: Return structured 10-point audit JSON
    api_payload = {
        "url": res["raw_url"],
        "final_url": res["final_url"],
        "score": res["score"],
        "grade": res["grade"],
        "timestamp": res["timestamp"],
        "checks": [
            {
                "name": c["name"],
                "category": c.get("category", "General"),
                "passed": c["passed"],
                "deducted": c["deducted"],
                "explanation": c["explanation"],
                "details": c.get("details", {}),
            }
            for c in res["checks"]
        ]
    }
    resp = jsonify(api_payload)
    resp.headers["X-RateLimit-Limit"] = str(scan_limiter.max_requests)
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    return resp


if __name__ == "__main__":
    app.run(debug=True)
