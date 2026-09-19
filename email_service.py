"""
email_service.py — Transactional Email Service for SecureScan
=============================================================
Handles sending security alert notifications to users when a monitored site
experiences a security score drop, grade degradation, or newly failing security checks.

Supported Providers:
1. Resend (Primary / Recommended)
   - Modern, lightweight REST API (`POST https://api.resend.com/emails`).
   - Driven by `RESEND_API_KEY` and optional `RESEND_FROM_EMAIL`.
   - Zero external SDK dependencies (uses `requests`).
2. Generic SMTP (Fallback)
   - Configured via `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`.
3. Mock / Test Mode
   - Activated if `SECURESCAN_MOCK_EMAIL=1` or when no API keys are present in dev/test.
   - Captures email payloads in memory for test assertions without burning quota.
"""

from __future__ import annotations

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, List, Dict, Any, Tuple

import requests

logger = logging.getLogger(__name__)

# Captured emails in mock/test mode
MOCK_SENT_EMAILS: List[Dict[str, Any]] = []


def is_mock_mode() -> bool:
    """Return True if mock mode is explicitly enabled or during testing."""
    return os.environ.get("SECURESCAN_MOCK_EMAIL", "").strip() == "1"


def get_mock_sent_emails() -> List[Dict[str, Any]]:
    """Retrieve all emails recorded in mock mode."""
    return list(MOCK_SENT_EMAILS)


def clear_mock_sent_emails() -> None:
    """Clear recorded mock emails."""
    MOCK_SENT_EMAILS.clear()


# ─── Attack Scenario Explanations ─────────────────────────────────────────────

CHECK_ATTACK_SCENARIOS: Dict[str, str] = {
    "Content Security Policy (CSP)": "Leaves the application vulnerable to Cross-Site Scripting (XSS) and arbitrary data injection by malicious inline scripts.",
    "HTTP Strict Transport Security (HSTS)": "Permits Man-in-the-Middle (MitM) attackers to strip SSL/TLS and intercept unencrypted session traffic.",
    "X-Frame-Options": "Permits UI redressing and Clickjacking attacks, tricking authenticated users into clicking hidden actions.",
    "X-Content-Type-Options": "Enables MIME-type sniffing, allowing attackers to execute malicious scripts disguised as harmless images or text.",
    "Referrer-Policy": "Risks leaking sensitive internal paths or session tokens in the HTTP Referer header to third-party endpoints.",
    "Permissions-Policy": "Allows embedded third parties to access sensitive device features like camera, microphone, or geolocation without restriction.",
    "SSL/TLS Configuration": "Exposes traffic to cryptographic downgrade attacks and eavesdropping via deprecated ciphers or protocols.",
    "Server Information Leakage": "Reveals server versions and infrastructure details, simplifying targeted vulnerability reconnaissance.",
    "Subresource Integrity (SRI)": "Leaves the site vulnerable to CDN compromise and supply-chain attacks on third-party assets.",
    "DNSSEC": "Exposes DNS records to spoofing and DNS cache poisoning attacks, potentially redirecting visitors to malicious clones.",
}


# ─── Email Template Builders ──────────────────────────────────────────────────

def build_security_alert_html(
    site_url: str,
    old_score: int,
    new_score: int,
    old_grade: str,
    new_grade: str,
    newly_failing_checks: List[Dict[str, Any]],
    scan_id: int,
    base_url: str,
    recipient_email: str,
) -> str:
    """
    Construct a clean, responsive, professional security advisory HTML email.
    """
    score_drop = old_score - new_score
    dashboard_url = f"{base_url.rstrip('/')}/dashboard/scan/{scan_id}"
    account_url = f"{base_url.rstrip('/')}/account"

    # Color tokens for email clients
    accent_red = "#dc2626"
    bg_dark = "#0b1329"
    card_bg = "#ffffff"
    border_color = "#e2e8f0"
    text_primary = "#0f172a"
    text_muted = "#64748b"

    # Format newly failing checks rows
    checks_html_rows = ""
    if newly_failing_checks:
        for idx, check in enumerate(newly_failing_checks, 1):
            name = check.get("name", f"Check {idx}")
            category = check.get("category", "Security Check")
            deducted = check.get("deducted", 0)
            explanation = check.get("explanation", "Security posture regression detected.")
            scenario = check.get("attack_scenario") or CHECK_ATTACK_SCENARIOS.get(name, "")

            scenario_block = ""
            if scenario:
                scenario_block = f"""
                <div style="margin-top: 8px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 12.5px; line-height: 1.45; color: #7f1d1d; background: #fff5f5; padding: 7px 10px; border-radius: 4px; border: 1px dashed #fca5a5;">
                  <strong>Threat / Attack Scenario:</strong> {scenario}
                </div>
                """

            checks_html_rows += f"""
            <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; border-radius: 4px; padding: 14px 16px; margin-bottom: 12px;">
              <table style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; font-weight: 700; color: #991b1b;">
                    ❌ {name}
                    <span style="font-size: 11px; font-weight: 600; color: #b91c1c; background: #fee2e2; padding: 2px 8px; border-radius: 12px; margin-left: 8px;">{category}</span>
                  </td>
                  <td style="text-align: right; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 13px; font-weight: 700; color: #b91c1c; white-space: nowrap;">
                    -{deducted} pts
                  </td>
                </tr>
              </table>
              <p style="margin: 8px 0 0 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 13.5px; line-height: 1.5; color: #374151;">
                {explanation}
              </p>
              {scenario_block}
            </div>
            """
    else:
        checks_html_rows = f"""
        <div style="background-color: #fffbeb; border-left: 4px solid #f59e0b; border-radius: 4px; padding: 14px 16px; margin-bottom: 12px;">
          <p style="margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 13.5px; color: #92400e;">
            Overall security score decreased by <strong>{score_drop} points</strong> (Grade {old_grade} → {new_grade}). No single check flipped completely, but accumulated security deductions were identified during the automated re-scan.
          </p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Alert: {site_url}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed;">
    <tr>
      <td align="center" style="padding: 30px 15px 40px 15px;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: {card_bg}; border-radius: 12px; overflow: hidden; border: 1px solid {border_color}; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);">
          
          <!-- Header Banner -->
          <tr>
            <td style="background-color: {bg_dark}; padding: 24px 28px;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td>
                    <span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 20px; font-weight: 800; color: #ffffff; letter-spacing: -0.5px;">
                      🔍 SecureScan
                    </span>
                    <span style="display: inline-block; background-color: #ef4444; color: #ffffff; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 12px; margin-left: 10px; text-transform: uppercase; letter-spacing: 0.5px; vertical-align: middle;">
                      Security Alert
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content -->
          <tr>
            <td style="padding: 28px 28px 20px 28px;">
              <h1 style="margin: 0 0 12px 0; font-size: 20px; font-weight: 700; color: {text_primary}; line-height: 1.3;">
                Security Regression Detected on <span style="color: #2563eb;">{site_url}</span>
              </h1>
              <p style="margin: 0 0 24px 0; font-size: 14.5px; line-height: 1.55; color: {text_muted};">
                Our scheduled monitoring service just finished an automated re-scan of your monitored domain. We detected meaningful security regressions that require your attention.
              </p>

              <!-- Score Comparison Box -->
              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 16px; text-align: center; width: 45%;">
                    <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #64748b; margin-bottom: 4px;">Previous Score</div>
                    <div style="font-size: 26px; font-weight: 800; color: #0f172a;">{old_score}<span style="font-size: 14px; font-weight: 500; color: #94a3b8;">/100</span></div>
                    <div style="font-size: 13px; font-weight: 700; color: #16a34a; margin-top: 2px;">Grade {old_grade}</div>
                  </td>
                  <td style="text-align: center; width: 10%; font-size: 20px; color: #94a3b8; font-weight: 700;">
                    →
                  </td>
                  <td style="padding: 16px; text-align: center; width: 45%;">
                    <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #dc2626; margin-bottom: 4px;">New Score</div>
                    <div style="font-size: 26px; font-weight: 800; color: #dc2626;">{new_score}<span style="font-size: 14px; font-weight: 500; color: #dc2626;">/100</span></div>
                    <div style="font-size: 13px; font-weight: 700; color: #dc2626; margin-top: 2px;">Grade {new_grade} (-{score_drop} pts)</div>
                  </td>
                </tr>
              </table>

              <!-- Newly Failing Checks Heading -->
              <h2 style="margin: 0 0 14px 0; font-size: 15px; font-weight: 700; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px;">
                Identified Security Regressions
              </h2>

              <!-- Checks List -->
              {checks_html_rows}

              <!-- CTA Button -->
              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 24px;">
                <tr>
                  <td align="center">
                    <a href="{dashboard_url}" target="_blank" style="display: inline-block; background: linear-gradient(135deg, #0ea5e9, #6366f1); color: #ffffff; text-decoration: none; font-size: 14.5px; font-weight: 700; padding: 13px 28px; border-radius: 8px; box-shadow: 0 4px 12px rgba(14, 165, 233, 0.25);">
                      Inspect Full Audit Report &amp; Recommendations →
                    </a>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #f8fafc; border-top: 1px solid #e2e8f0; padding: 20px 28px; text-align: center;">
              <p style="margin: 0 0 6px 0; font-size: 12.5px; color: #64748b;">
                You received this alert because <strong>{site_url}</strong> is active in your monitored sites list.
              </p>
              <p style="margin: 0; font-size: 12px; color: #94a3b8;">
                <a href="{account_url}" target="_blank" style="color: #6366f1; text-decoration: underline;">Manage Notification Preferences</a>
                &nbsp;·&nbsp;
                <a href="{account_url}" target="_blank" style="color: #6366f1; text-decoration: underline;">Unsubscribe from Site Alerts</a>
                &nbsp;·&nbsp;
                <a href="{base_url}" target="_blank" style="color: #64748b; text-decoration: none;">SecureScan Security Auditor</a>
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
    return html


def build_security_alert_text(
    site_url: str,
    old_score: int,
    new_score: int,
    old_grade: str,
    new_grade: str,
    newly_failing_checks: List[Dict[str, Any]],
    scan_id: int,
    base_url: str,
) -> str:
    """
    Construct a plain-text fallback version of the security alert email.
    """
    score_drop = old_score - new_score
    dashboard_url = f"{base_url.rstrip('/')}/dashboard/scan/{scan_id}"
    account_url = f"{base_url.rstrip('/')}/account"

    lines = [
        f"SECURESCAN SECURITY ALERT: Regression Detected on {site_url}",
        "=" * 60,
        f"Target Domain:  {site_url}",
        f"Previous Score: {old_score}/100 (Grade {old_grade})",
        f"New Score:      {new_score}/100 (Grade {new_grade})",
        f"Net Change:     -{score_drop} points",
        "",
        "IDENTIFIED REGRESSIONS / NEWLY FAILING CHECKS:",
        "-" * 60,
    ]

    if newly_failing_checks:
        for idx, check in enumerate(newly_failing_checks, 1):
            name = check.get("name", f"Check {idx}")
            deducted = check.get("deducted", 0)
            explanation = check.get("explanation", "Regression detected.")
            scenario = check.get("attack_scenario") or CHECK_ATTACK_SCENARIOS.get(name, "")
            lines.append(f"{idx}. [FAILED] {name} (-{deducted} pts)")
            lines.append(f"   Details: {explanation}")
            if scenario:
                lines.append(f"   Threat Scenario: {scenario}")
            lines.append("")
    else:
        lines.append(f"Overall security score dropped by {score_drop} points.")
        lines.append("")

    lines.extend([
        "-" * 60,
        f"View the full audit findings and remediation guide:",
        f"{dashboard_url}",
        "",
        f"Manage notification preferences or unsubscribe:",
        f"{account_url}",
        "",
        "--",
        "SecureScan Automated Monitoring",
    ])

    return "\n".join(lines)


# ─── Email Dispatch Drivers ───────────────────────────────────────────────────

def _send_via_resend(
    api_key: str,
    from_email: str,
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str,
) -> Tuple[bool, str]:
    """
    Send an email using Resend REST API (https://api.resend.com/emails).
    """
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "html": html_content,
        "text": text_content,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=12)
        if resp.status_code in (200, 201):
            data = resp.json()
            email_id = data.get("id", "ok")
            logger.info(f"Resend email dispatched successfully to {to_email} (ID: {email_id})")
            return True, email_id
        else:
            err_msg = f"Resend API error HTTP {resp.status_code}: {resp.text[:300]}"
            logger.error(err_msg)
            return False, err_msg
    except Exception as exc:
        err_msg = f"Resend network/request exception: {exc}"
        logger.error(err_msg)
        return False, err_msg


def _send_via_smtp(
    host: str,
    port: int,
    user: str,
    password: str,
    from_email: str,
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str,
) -> Tuple[bool, str]:
    """
    Send an email via standard SMTP (TLS).
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            server.starttls()

        if user and password:
            server.login(user, password)

        server.sendmail(from_email, [to_email], msg.as_string())
        server.quit()
        logger.info(f"SMTP email sent successfully to {to_email}")
        return True, "smtp_success"
    except Exception as exc:
        err_msg = f"SMTP error: {exc}"
        logger.error(err_msg)
        return False, err_msg


# ─── Public API ───────────────────────────────────────────────────────────────

def send_security_alert_email(
    to_email: Optional[str] = None,
    site_url: Optional[str] = None,
    old_score: Optional[int] = None,
    new_score: Optional[int] = None,
    old_grade: Optional[str] = None,
    new_grade: Optional[str] = None,
    newly_failing_checks: Optional[List[Dict[str, Any]]] = None,
    scan_id: int = 0,
    base_url: str = "https://project-secure-scan-20.vercel.app",
    *,
    recipient_email: Optional[str] = None,
    target_url: Optional[str] = None,
    prev_score: Optional[int] = None,
    curr_score: Optional[int] = None,
    prev_grade: Optional[str] = None,
    curr_grade: Optional[str] = None,
    reasons: Optional[List[str]] = None,
    **kwargs: Any,
) -> bool:
    """
    Public entry point to dispatch a security regression alert email.

    Supports both positional and keyword invocations, accommodating aliases
    (recipient_email, target_url, prev_score/curr_score, prev_grade/curr_grade).
    Returns True if successfully dispatched/mocked, False on failure.
    """
    dest_email = (to_email or recipient_email or "").strip()
    if not dest_email:
        logger.error("send_security_alert_email: No recipient email provided.")
        return False

    url_target = site_url or target_url or ""
    score_before = old_score if old_score is not None else (prev_score if prev_score is not None else 0)
    score_after = new_score if new_score is not None else (curr_score if curr_score is not None else 0)
    grade_before = old_grade or prev_grade or "B"
    grade_after = new_grade or curr_grade or "C"
    failing_list = newly_failing_checks or []

    subject = f"🚨 Security Alert: {url_target} score dropped to {score_after}/100 (Grade {grade_after})"
    from_email = os.environ.get("RESEND_FROM_EMAIL", "SecureScan Alerts <onboarding@resend.dev>")

    html_content = build_security_alert_html(
        site_url=url_target,
        old_score=score_before,
        new_score=score_after,
        old_grade=grade_before,
        new_grade=grade_after,
        newly_failing_checks=failing_list,
        scan_id=scan_id,
        base_url=base_url,
        recipient_email=dest_email,
    )

    text_content = build_security_alert_text(
        site_url=url_target,
        old_score=score_before,
        new_score=score_after,
        old_grade=grade_before,
        new_grade=grade_after,
        newly_failing_checks=failing_list,
        scan_id=scan_id,
        base_url=base_url,
    )

    # 1. Explicit Mock Mode
    if is_mock_mode():
        MOCK_SENT_EMAILS.append({
            "to": dest_email,
            "from": from_email,
            "subject": subject,
            "site_url": url_target,
            "old_score": score_before,
            "new_score": score_after,
            "old_grade": grade_before,
            "new_grade": grade_after,
            "newly_failing_checks": failing_list,
            "scan_id": scan_id,
            "html": html_content,
            "text": text_content,
        })
        logger.info(f"[MOCK EMAIL] Recorded alert to {dest_email} for {url_target}")
        return True

    # 2. Resend API
    resend_api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if resend_api_key:
        ok, msg = _send_via_resend(
            api_key=resend_api_key,
            from_email=from_email,
            to_email=dest_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
        )
        return ok

    # 3. SMTP
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    if smtp_host:
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_user = os.environ.get("SMTP_USER", "").strip()
        smtp_pass = os.environ.get("SMTP_PASS", "").strip()
        smtp_from = os.environ.get("SMTP_FROM", from_email)
        ok, msg = _send_via_smtp(
            host=smtp_host,
            port=smtp_port,
            user=smtp_user,
            password=smtp_pass,
            from_email=smtp_from,
            to_email=dest_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
        )
        return ok

    # 4. Fallback if no provider is configured: record in mock list and log notice
    logger.warning(
        f"No email provider configured (RESEND_API_KEY or SMTP_HOST missing). "
        f"Alert for {url_target} recorded in mock cache."
    )
    MOCK_SENT_EMAILS.append({
        "to": dest_email,
        "from": from_email,
        "subject": subject,
        "site_url": url_target,
        "old_score": score_before,
        "new_score": score_after,
        "old_grade": grade_before,
        "new_grade": grade_after,
        "newly_failing_checks": failing_list,
        "scan_id": scan_id,
        "html": html_content,
        "text": text_content,
    })
    return True

