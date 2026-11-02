"""
================================================================
SECURITY MODULE
================================================================
- Flask-Limiter (IP rate limiting)
- Risk scoring / Risk Based Authentication decision engine
- OTP generation + hashing helpers
- Account lock logic
- Security response headers
================================================================
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from flask import request, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from models import db, User

# ============================================================
# RATE LIMITER (IP based)
# ============================================================

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=Config.RATELIMIT_STORAGE_URI,
    headers_enabled=Config.RATELIMIT_HEADERS_ENABLED,
)

# ============================================================
# RISK BASED AUTHENTICATION ENGINE
# ============================================================

RISK_HIGH_THRESHOLD = 80
RISK_MEDIUM_THRESHOLD = 40


def get_risk_level(score):
    """Returns risk level based on risk score."""
    if score >= RISK_HIGH_THRESHOLD:
        return "High"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def decide_auth_policy(score):
    """
    Converts a risk score into an authentication decision:

        Low    -> "allow"  (password verified, optional MFA)
        Medium -> "mfa"    (MFA is mandatory)
        High   -> "block"  (login is refused)
    """
    level = get_risk_level(score)
    if level == "High":
        return "block"
    if level == "Medium":
        return "mfa"
    return "allow"


def sensitive_operation_blocked(user):
    """
    Risk gate for sensitive operations (download / delete / password
    change).

        Low/Medium -> not blocked; an Email OTP step-up is required.
        High       -> blocked + account locked + alert (caller handles).

    Returns (blocked: bool, reason: str|None).
    """
    if user.risk_score >= RISK_HIGH_THRESHOLD:
        return True, (
            "Operation blocked due to high risk. "
            "Your account has been locked for security."
        )
    return False, None


# ============================================================
# OTP
# ============================================================

def generate_otp():
    """Returns a cryptographically secure 6-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp):
    """SHA-256 of the OTP - plaintext is never stored."""
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def issue_stepup_otp(user, kind, ttl_seconds=None, reset_resends=True):
    """
    Issues + stores a Step-Up OTP for a sensitive operation.
    kind is one of: "download", "delete", "password".
    Returns the plaintext OTP (used for the email + dev box).
    The plaintext OTP is never persisted - only its SHA-256 hash.

    reset_resends=False is used by the resend flow so the resend
    counter keeps accumulating toward OTP_MAX_RESENDS.
    """
    ttl = ttl_seconds or Config.OTP_TTL_SECONDS
    otp = generate_otp()
    user.set_stepup_otp(kind, otp, ttl)
    if reset_resends:
        setattr(user, f"{kind}_otp_resends", 0)
    db.session.commit()
    return otp


# ============================================================
# ACCOUNT LOCK
# ============================================================

def is_account_locked(user):
    """
    Returns True if the account is locked.
    Automatically unlocks after locked_until passes.
    """
    if not user.account_locked:
        return False

    if user.locked_until is None:
        if user.lock_time is not None:
            user.locked_until = user.lock_time + timedelta(
                minutes=Config.LOCK_DURATION_MINUTES
            )
            db.session.commit()
        else:
            return True

    if datetime.utcnow() >= user.locked_until:
        user.account_locked = False
        user.failed_attempts = 0
        user.lock_time = None
        user.locked_until = None
        db.session.commit()
        return False

    return True


def lock_account(user, duration_minutes=None):
    """Locks the account until locked_until (default = LOCK_DURATION_MINUTES)."""
    minutes = duration_minutes or Config.LOCK_DURATION_MINUTES
    now = datetime.utcnow()
    user.account_locked = True
    user.lock_time = now
    user.locked_until = now + timedelta(minutes=minutes)


# ============================================================
# CLIENT CONTEXT HELPERS
# ============================================================

def get_client_ip():
    """Returns the client IP (respects X-Forwarded-For)."""
    if has_request_context():
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "Unknown"
    return "Unknown"


def get_device():
    """Returns the device / User-Agent string."""
    if has_request_context():
        return request.headers.get("User-Agent", "Unknown")
    return "Unknown"


def get_browser():
    """Best-effort browser name parsed from the User-Agent."""
    ua = get_device().lower()
    if "edg/" in ua or "edge/" in ua:
        return "Edge"
    if "chrome/" in ua:
        return "Chrome"
    if "firefox/" in ua:
        return "Firefox"
    if "safari/" in ua:
        return "Safari"
    if "opera" in ua or "opr/" in ua:
        return "Opera"
    if "curl" in ua or "wget" in ua or "python" in ua:
        return "CLI / API client"
    return "Unknown"


def get_os():
    """Best-effort OS name parsed from the User-Agent."""
    ua = get_device().lower()
    if "windows" in ua:
        return "Windows"
    if "android" in ua:
        return "Android"
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        return "iOS"
    if "mac os" in ua or "macintosh" in ua:
        return "macOS"
    if "linux" in ua:
        return "Linux"
    return "Unknown"


def get_location():
    """Best-effort location. Returns 'Unknown' when geo lookup is
    not configured (no external geolocation service in this project)."""
    return "Unknown"


def promote_admin_if_needed(user):
    """Promotes users listed in ADMIN_EMAILS to admin role."""
    if not user.is_admin and user.email in Config.ADMIN_EMAILS:
        user.is_admin = True
        db.session.commit()
        return True
    return False


# ============================================================
# SECURITY RESPONSE HEADERS
# ============================================================

def apply_security_headers(response):
    """
    Adds OWASP-recommended security headers to every response.

    Note: script/style sources allow 'unsafe-inline' because the
    current templates use inline handlers. For strict production
    hardening, move to external assets and a nonce-based CSP.
    """
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # HSTS only when actually served over HTTPS. Sending it on plain
    # http://localhost would make browsers permanently refuse the site.
    secure = (
        request.is_secure
        or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
        or Config.SESSION_COOKIE_SECURE
    )
    if secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response
