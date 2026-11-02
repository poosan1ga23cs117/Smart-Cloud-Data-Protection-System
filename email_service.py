"""
================================================================
EMAIL SERVICE MODULE
================================================================
Gmail SMTP (App Password) delivery for:

  - Email OTP (login verification)       -> "Your OTP Code"
  - Account Lock                          -> "Account Locked"
  - Account Unlock OTP                    -> "Account Unlock Verification"
  - High Risk Login Alert                 -> "High Risk Login Attempt Detected"
  - New Device Login Alert                -> "New Device Login"
  - Multiple Failed Login Warning         -> "Multiple Failed Login Attempts"
  - Password Changed                       -> "Password Changed Successfully"
  - File Uploaded                          -> "File Uploaded Successfully"
  - File Downloaded                        -> "File Downloaded"
  - File Integrity / Tampering Alert       -> "File Integrity Alert"
  - Download Step-Up OTP                   -> "Download Verification OTP"
  - Delete Step-Up OTP                     -> "Delete File Verification OTP"
  - Password Change Step-Up OTP            -> "Password Change Verification OTP"
  - File Deleted Confirmation              -> "File Deleted Successfully"
  - Repeated Operation Attempt Alerts      -> Repeated Download / Delete /
                                               Password Change Attempts
  - Multiple Invalid OTP Attempts          -> "Multiple Invalid OTP Attempts"

All messages use a professional HTML template with the project
logo, the "Smart Cloud Security" brand, a security footer and
clear OTP guidance ("Do not share this OTP", "OTP valid for X").

Configuration comes ONLY from .env (MAIL_SERVER, MAIL_PORT,
MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD) using a Gmail App
Password. Google OAuth is NOT used.

If MAIL_ENABLED is false, messages are logged to the console so
the system remains fully usable for local demos and testing.
================================================================
"""

import base64
import logging
import os
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import Config

logger = logging.getLogger("email_service")

PROJECT_NAME = "Smart Cloud Security"

# Inline SVG cloud logo (self-contained, no external assets needed
# in email clients which often block remote images).
_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="44" height="44" '
    'viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="1.6" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>'
    '<path d="M2 12h3M4 8l1.5 1.5M4 16l1.5-1.5"/>'
    "</svg>"
)
_LOGO_B64 = base64.b64encode(_LOGO_SVG.encode("utf-8")).decode("ascii")

BRAND = (
    "<img src='data:image/svg+xml;base64,"
    + _LOGO_B64
    + "' alt='logo' width='44' height='44' style='display:inline-block;"
    "vertical-align:middle;margin-right:12px'>"
)


def _html_template(subject, content):
    """Wraps inner content in the branded, professional HTML layout."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{subject} | {PROJECT_NAME}</title>
</head>
<body style="margin:0;padding:0;background-color:#F1F5F9;
font-family:'Segoe UI',Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"
       style="background-color:#F1F5F9;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:600px;margin:0 auto;
background-color:#FFFFFF;border:1px solid #E2E8F0;border-radius:12px;
overflow:hidden;">
<tr><td style="background:linear-gradient(135deg,#0F172A 0%,#1E3A5F 100%);
padding:22px 28px;">
  <span style="display:inline-block;vertical-align:middle;">{BRAND}</span>
  <span style="color:#FFFFFF;font-size:20px;font-weight:700;
  vertical-align:middle;letter-spacing:0.3px;">{PROJECT_NAME}</span>
  <div style="color:#94A3B8;font-size:12px;margin-top:4px;">
    Zero Trust Cloud Data Protection
  </div>
</td></tr>
<tr><td style="padding:30px 28px;color:#1E293B;font-size:15px;
line-height:1.6;">
  {content}
</td></tr>
<tr><td style="background-color:#F8FAFC;border-top:1px solid #E2E8F0;
padding:18px 28px;color:#64748B;font-size:12px;line-height:1.7;">
  <div style="font-weight:700;color:#334155;">{PROJECT_NAME}</div>
  <div style="margin-top:2px;">Zero Trust Architecture &nbsp;|&nbsp;
  AES-256-GCM Encryption &nbsp;|&nbsp; SHA-256 Integrity &nbsp;|&nbsp;
  Immutable Audit Logs</div>
  <div style="margin-top:8px;color:#94A3B8;">
    If you did not request this email, ignore it or change your password
    immediately. For your security, never share one-time passwords.
  </div>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
""".strip()


def _html_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _info_rows(rows):
    """Renders a list of (label, value) tuples as an info table."""
    html = [
        "<table role='presentation' width='100%' cellspacing='0' "
        "cellpadding='0' style='margin:12px 0;'>"
    ]
    for label, value in rows:
        html.append(
            "<tr><td style='padding:5px 0;color:#64748B;width:130px;"
            "font-size:13px;vertical-align:top;'>{}</td>"
            "<td style='padding:5px 0;color:#1E293B;font-size:14px;"
            "font-weight:600;'>{}</td></tr>".format(
                _html_escape(label), _html_escape(value)
            )
        )
    html.append("</table>")
    return "".join(html)


def _otp_box(otp, validity_text):
    """Highlighted OTP code box used in OTP emails."""
    return (
        "<div style='margin:18px 0;padding:18px;border:2px dashed #22D3EE;"
        "background-color:#F0FDFF;border-radius:10px;text-align:center;'>"
        "<div style='font-size:13px;color:#0E7490;letter-spacing:1px;"
        "text-transform:uppercase;margin-bottom:8px;'>"
        "Do not share this OTP</div>"
        f"<div style='font-size:34px;font-weight:800;letter-spacing:10px;"
        f"color:#0F172A;'>{_html_escape(otp)}</div>"
        f"<div style='font-size:12px;color:#64748B;margin-top:8px;'>"
        f"Validity: {validity_text}</div>"
        "</div>"
    )


class EmailService:
    """Thread-safe SMTP mailer."""

    def send(self, to_email, subject, body):
        if not to_email:
            return False

        if not getattr(Config, "MAIL_ENABLED", False) or not Config.MAIL_SERVER:
            # Never log the body - it may contain the OTP.
            logger.info(
                "[MAIL DISABLED] To=%s | Subject=%s",
                to_email,
                subject,
            )
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = Config.MAIL_FROM
            msg["To"] = to_email
            msg.attach(MIMEText(body, "plain"))
            msg.attach(
                MIMEText(
                    _html_template(subject, body),
                    "html",
                )
            )

            server = smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT)
            if Config.MAIL_USE_TLS:
                server.starttls()
            if Config.MAIL_USERNAME:
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.sendmail(Config.MAIL_FROM, [to_email], msg.as_string())
            server.quit()
            return True
        except Exception:  # noqa: BLE001
            # Log the full exception/traceback so delivery failures are
            # visible on the server. Never expose the OTP in the message.
            logger.exception(
                "[MAIL ERROR] Failed to send email to %s", to_email
            )
            return False

    def send_async(self, to_email, subject, body):
        thread = threading.Thread(
            target=self.send,
            args=(to_email, subject, body),
            daemon=True,
        )
        thread.start()


service = EmailService()


# ------------------------------------------------------------
# OTP delivery helpers and messages
# ------------------------------------------------------------

# Production-facing confirmation shown when an OTP is issued.
OTP_SENT_MESSAGE = "A 6-digit OTP has been sent to your registered email."

# Shown when an email OTP cannot be delivered (production only).
OTP_SEND_FAILURE = "Unable to send OTP. Please try again later."


def dev_otp_visible():
    """OTP may be revealed ONLY during local development: DEV_MODE == True
    AND Flask debug mode enabled. In every other environment (EC2 /
    production) the OTP is never displayed anywhere."""
    return bool(
        getattr(Config, "DEV_MODE", False)
        and getattr(Config, "DEBUG", False)
    )


def otp_message(dev_message):
    """User-facing confirmation for an issued OTP.
    Production shows ONLY OTP_SENT_MESSAGE; development keeps the
    contextual message (and may reveal the OTP in the dev box)."""
    return dev_message if dev_otp_visible() else OTP_SENT_MESSAGE


def deliver_otp(send_func, *args):
    """Attempts to deliver an OTP by email.
    Returns True when the OTP reached the user: either the email was sent,
    OR the dev box is available (DEV_MODE + debug).
    In production a failed send returns False so the caller can show
    OTP_SEND_FAILURE and MUST never reveal the OTP as a fallback."""
    return bool(send_func(*args)) or dev_otp_visible()


# ------------------------------------------------------------
# OTP EMAILS
# ------------------------------------------------------------

def send_otp(to_email, otp, ttl_seconds=None):
    ttl = ttl_seconds or getattr(Config, "OTP_TTL_SECONDS", 300)
    minutes = max(1, round(ttl / 60))
    validity = f"OTP valid for {minutes} minute"
    if minutes > 1:
        validity += "s"
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Use the one-time password below to complete your login "
        f"verification.</p>"
        f"{_otp_box(otp, validity)}"
        "<p style='font-size:13px;color:#64748B;'>"
        "Never share this OTP with anyone. Our team will never ask for it.</p>"
        "<p>If you did not attempt to log in, your account may be at risk - "
        "change your password immediately.</p>"
    )
    return service.send(
        to_email, f"[{PROJECT_NAME}] Your Login OTP", body
    )


def send_unlock_otp(to_email, otp, ttl_seconds=None):
    ttl = ttl_seconds or getattr(Config, "UNLOCK_OTP_TTL_SECONDS", 600)
    minutes = max(1, round(ttl / 60))
    validity = f"expires in {minutes} minutes"
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Your account was locked. Use the OTP below to unlock it. "
        f"It {validity}.</p>"
        f"{_otp_box(otp, validity)}"
        "<p style='font-size:13px;color:#64748B;'>"
        "Do not share this OTP with anyone.</p>"
        "<p>If you did not request this unlock, your account may be at "
        "risk - change your password immediately.</p>"
    )
    return service.send(
        to_email, "Account Unlock Verification", body
    )


# ------------------------------------------------------------
# STEP-UP OTP EMAILS (sensitive operations)
# ------------------------------------------------------------

def send_download_otp(to_email, otp, ttl_seconds=None):
    """OTP required before any file download is authorized."""
    ttl = ttl_seconds or getattr(Config, "OTP_TTL_SECONDS", 300)
    minutes = max(1, round(ttl / 60))
    validity = f"OTP valid for {minutes} minute"
    if minutes > 1:
        validity += "s"
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>A request was made to <b>download a file</b> from your cloud "
        "storage. To confirm this action, enter the one-time password "
        "below.</p>"
        f"{_otp_box(otp, validity)}"
        "<p style='font-size:13px;color:#64748B;'>"
        "Never share this OTP with anyone. Our team will never ask for it.</p>"
        "<p>If you did not request this download, your account may be at "
        "risk - change your password immediately.</p>"
    )
    return service.send(
        to_email, "Download Verification OTP", body
    )


def send_delete_otp(to_email, otp, filename, ttl_seconds=None):
    """OTP required before a file can be permanently deleted."""
    ttl = ttl_seconds or getattr(Config, "OTP_TTL_SECONDS", 300)
    minutes = max(1, round(ttl / 60))
    validity = f"OTP valid for {minutes} minute"
    if minutes > 1:
        validity += "s"
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>A request was made to <b>permanently delete</b> the file "
        f"<b>{_html_escape(filename)}</b> from your cloud storage.</p>"
        "<p>Deletion is irreversible. To confirm this action, enter the "
        "one-time password below.</p>"
        f"{_otp_box(otp, validity)}"
        "<p style='font-size:13px;color:#64748B;'>"
        "Never share this OTP with anyone. Our team will never ask for it.</p>"
        "<p>If you did not request this deletion, your account may be at "
        "risk - change your password immediately.</p>"
    )
    return service.send(
        to_email, "Delete File Verification OTP", body
    )


def send_password_change_otp(to_email, otp, ttl_seconds=None):
    """OTP required before the account password can be changed."""
    ttl = ttl_seconds or getattr(Config, "OTP_TTL_SECONDS", 300)
    minutes = max(1, round(ttl / 60))
    validity = f"OTP valid for {minutes} minute"
    if minutes > 1:
        validity += "s"
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>A request was made to <b>change your account password</b>. "
        "To confirm this action, enter the one-time password below.</p>"
        f"{_otp_box(otp, validity)}"
        "<p style='font-size:13px;color:#64748B;'>"
        "Never share this OTP with anyone. Our team will never ask for it.</p>"
        "<p>If you did not request this change, your account may be at "
        "risk - contact support immediately.</p>"
    )
    return service.send(
        to_email, "Password Change Verification OTP", body
    )


def send_alert(to_email, subject, body):
    service.send_async(to_email, subject, body)


def notify_admin(subject, body):
    admin_email = getattr(Config, "ADMIN_EMAIL", "") or ""
    if admin_email:
        service.send_async(admin_email, subject, body)


# ------------------------------------------------------------
# SECURITY ALERTS
# ------------------------------------------------------------

def alert_new_login(to_email, ip, device, timestamp):
    """Generic login notification (kept for compatibility)."""
    info = _info_rows([
        ('Time', timestamp),
        ('IP', ip),
        ('Device', device),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>A new login to your account was detected.</p>"
        f"{info}"
        "<p style='font-size:13px;color:#64748B;'>"
        "If this was not you, change your password immediately.</p>"
    )
    send_alert(
        to_email,
        f"[{PROJECT_NAME}] New Login Detected",
        body,
    )


def alert_new_device(to_email, device, browser, os_name, ip, timestamp):
    """Sent when a login happens from a new device / IP."""
    info = _info_rows([
        ('Device', device),
        ('Browser', browser),
        ('Operating System', os_name),
        ('IP Address', ip),
        ('Time', timestamp),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>We detected a login to your account from a <b>new device</b>."
        f"</p>"
        f"{info}"
        "<p style='font-size:13px;color:#64748B;'>"
        "If this was not you, someone may have your password. Change your "
        "password immediately.</p>"
    )
    send_alert(
        to_email,
        "New Device Login",
        body,
    )


def alert_high_risk(to_email, ip, browser, os_name, location, timestamp, score):
    info = _info_rows([
        ('Time', timestamp),
        ('IP Address', ip),
        ('Browser', browser),
        ('Operating System', os_name),
        ('Location', location),
        ('Risk Score', f'{score} (High)'),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>A <b>high-risk login attempt</b> was detected on your account "
        "and <b>blocked</b> by Risk Based Authentication.</p>"
        f"{info}"
        "<p>Your account has been locked and can be opened again only via "
        "OTP verification.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If this was not you, your credentials may be compromised - change "
        "your password immediately.</p>"
    )
    send_alert(
        to_email,
        "High Risk Login Attempt Detected",
        body,
    )
    notify_admin(
        "[ALERT] High Risk Login Attempt Detected",
        f"User  : {to_email}\nIP    : {ip}\nBrowser: {browser}\n"
        f"OS    : {os_name}\nRisk  : {score} (High)\n"
        "The login was blocked and the account locked.",
    )


def alert_high_risk_operation(to_email, operation, filename=None, score=0):
    """Sent when a sensitive operation is blocked for a HIGH risk account."""
    info = _info_rows([
        ('Operation', operation.title()),
        ('Filename', filename or '-'),
        ('Risk Score', f'{score} (High)'),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>A <b>high-risk {_html_escape(operation)} attempt</b> was "
        "detected on your account and <b>blocked</b> by Risk Based "
        "Authentication.</p>"
        f"{info}"
        "<p>Your account has been locked for security.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If this was not you, your credentials may be compromised - change "
        "your password immediately.</p>"
    )
    send_alert(
        to_email,
        "High Risk Operation Blocked",
        body,
    )
    notify_admin(
        "[ALERT] High Risk Operation Blocked",
        f"User      : {to_email}\nOperation: {operation}\n"
        f"Filename  : {filename or '-'}\nRisk      : {score} (High)\n"
        "The operation was blocked and the account locked.",
    )


def alert_risk_mfa(to_email, ip, device, score):
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>A login attempt was made from an unusual context with a risk "
        f"score of {score}.</p>"
        f"{_info_rows([('IP', ip), ('Device', device)])}"
        "<p>For your security, an OTP has been sent to complete login.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If this was not you, change your password immediately.</p>"
    )
    send_alert(
        to_email,
        f"[{PROJECT_NAME}] Unusual Login Detected - Verify with OTP",
        body,
    )


def alert_account_locked(to_email, attempts, locked_until=None):
    info = _info_rows([
        ('Failed Attempts', attempts),
        ('Locked Until', locked_until),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Your account has been <b>locked</b> after "
        f"{attempts} failed login attempts.</p>"
        f"{info}"
        "<p>An unlock OTP was sent to your email so you can verify your "
        "identity and regain access immediately.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If you did not make these attempts, someone may be trying to "
        "access your account. Change your password after unlocking.</p>"
    )
    send_alert(
        to_email,
        "Account Locked",
        body,
    )


def alert_multiple_failed(to_email, attempts):
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>We detected {attempts} failed login attempts on your account."
        f"</p>"
        "<p>If this was you, double check your password.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If it was not you, someone may be trying to access your account.</p>"
    )
    send_alert(
        to_email,
        f"[{PROJECT_NAME}] Multiple Failed Login Attempts",
        body,
    )


def alert_password_changed(to_email, ip, timestamp=None, browser=None, os_name=None):
    info = _info_rows([
        ('Time', timestamp),
        ('IP Address', ip),
        ('Browser', browser or 'Unknown'),
        ('Operating System', os_name or 'Unknown'),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>Your account password was <b>changed successfully</b>. "
        "All active sessions were logged out for your security.</p>"
        f"{info}"
        "<p style='font-size:13px;color:#64748B;'>"
        "If you did not do this, reset your password immediately.</p>"
    )
    send_alert(
        to_email,
        "Password Changed Successfully",
        body,
    )


# ------------------------------------------------------------
# FILE ACTIVITY ALERTS
# ------------------------------------------------------------

def alert_file_uploaded(to_email, filename, fragments, timestamp=None):
    info = _info_rows([
        ('Filename', filename),
        ('Upload Time', timestamp),
        ('Encryption', 'AES-256-GCM (unique key)'),
        ('Fragments', fragments),
        ('Integrity', 'SHA-256 stored'),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Your file <b>{_html_escape(filename)}</b> was uploaded "
        f"securely.</p>"
        f"{info}"
        "<p style='font-size:13px;color:#64748B;'>"
        "The file was encrypted, fragmented and verified before upload.</p>"
    )
    send_alert(
        to_email,
        "File Uploaded Successfully",
        body,
    )


def alert_file_downloaded(to_email, filename, timestamp=None):
    info = _info_rows([
        ('Filename', filename),
        ('Download Time', timestamp),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Your file <b>{_html_escape(filename)}</b> was downloaded.</p>"
        f"{info}"
        "<p style='font-size:13px;color:#64748B;'>"
        "SHA-256 integrity was verified before decryption.</p>"
    )
    send_alert(
        to_email,
        "File Downloaded",
        body,
    )


def alert_tampering(to_email, filename, reason):
    info = _info_rows([
        ('Filename', filename),
        ('Reason', reason),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>A <b>file integrity alert</b> was raised for your file "
        f"<b>{_html_escape(filename)}</b>.</p>"
        f"{info}"
        "<p>The download was <b>blocked</b> because the data may have "
        "been tampered with. The event has been recorded in the audit log."
        "</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "Contact your administrator if you believe this is an error.</p>"
    )
    send_alert(
        to_email,
        "File Integrity Alert",
        body,
    )
    notify_admin(
        "[ALERT] File Tampering Detected",
        f"File  : {filename}\nReason: {reason}\nOwner : {to_email}\n"
        "The download was blocked and the event was logged.",
    )


def send_file_deleted(to_email, filename, timestamp=None):
    """Confirmation email sent after a file is permanently deleted."""
    info = _info_rows([
        ('Filename', filename),
        ('Deletion Time', timestamp),
    ])
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Your file <b>{_html_escape(filename)}</b> was "
        f"<b>permanently deleted</b> from cloud storage.</p>"
        f"{info}"
        "<p>Encrypted fragments were removed from storage and the file "
        "record was removed from your account.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If you did not do this, your account may be at risk - change "
        "your password immediately.</p>"
    )
    send_alert(
        to_email,
        "File Deleted Successfully",
        body,
    )


# ------------------------------------------------------------
# REPEATED ATTEMPT ALERTS (step-up operations)
# ------------------------------------------------------------

def alert_repeated_download_attempts(to_email):
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>Multiple download attempts have been made on your account in "
        "a short period of time.</p>"
        "<p>If this was you, a fresh OTP was sent to complete the download.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If it was not you, someone may be trying to access your files. "
        "Change your password immediately.</p>"
    )
    send_alert(
        to_email,
        "Repeated Download Attempts Detected",
        body,
    )
    notify_admin(
        "[ALERT] Repeated Download Attempts",
        f"User : {to_email}\n"
        "Multiple download attempts were detected on this account.",
    )


def alert_repeated_delete_attempts(to_email, filename):
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Multiple <b>deletion attempts</b> were detected for the file "
        f"<b>{_html_escape(filename)}</b>.</p>"
        "<p>Deletion is irreversible. The file has <b>not</b> been deleted "
        "until the OTP is verified successfully.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If it was not you, someone may be trying to delete your files. "
        "Change your password immediately.</p>"
    )
    send_alert(
        to_email,
        "Repeated Delete Attempts Detected",
        body,
    )
    notify_admin(
        "[ALERT] Repeated Delete Attempts",
        f"User : {to_email}\nFile : {filename}\n"
        "Multiple deletion attempts were detected on this account.",
    )


def alert_repeated_password_change_attempts(to_email):
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        "<p>Multiple <b>password change</b> requests were detected on your "
        "account in a short period of time.</p>"
        "<p>Your password has <b>not</b> been changed until the OTP is "
        "verified successfully.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If it was not you, someone may be trying to take over your "
        "account. Contact support immediately.</p>"
    )
    send_alert(
        to_email,
        "Repeated Password Change Attempts Detected",
        body,
    )
    notify_admin(
        "[ALERT] Repeated Password Change Attempts",
        f"User : {to_email}\n"
        "Multiple password change requests were detected on this account.",
    )


def alert_multiple_otp_failures(to_email, operation):
    body = (
        f"<p>Hi {_html_escape(to_email)},</p>"
        f"<p>Multiple invalid OTP attempts were made for the "
        f"<b>{_html_escape(operation)}</b> operation on your account.</p>"
        "<p>A fresh OTP has been sent to your email so the operation can "
        "be completed securely.</p>"
        "<p style='font-size:13px;color:#64748B;'>"
        "If it was not you, someone may be trying to access your account. "
        "Change your password immediately.</p>"
    )
    send_alert(
        to_email,
        "Multiple Invalid OTP Attempts",
        body,
    )
