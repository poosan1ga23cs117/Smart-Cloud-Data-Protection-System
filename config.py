import os

from dotenv import load_dotenv

# ============================================================
# CONFIGURATION
# All secrets are loaded from .env - NEVER hardcode keys here.
# ============================================================

basedir = os.path.abspath(os.path.dirname(__file__))
# Load .env so every secret/flag can come from a file when the process
# environment does not provide it (e.g. local development).
# IMPORTANT: values already present in the process environment (such as
# AWS_* variables injected by EC2 / a cloud host) are kept - .env only
# fills in anything missing. This is what makes the app work on EC2
# without any .env file.
load_dotenv(os.path.join(basedir, ".env"))
# Also pick up a .env from the process working directory (e.g. an
# EC2 deployment that keeps its .env next to the launch command).
load_dotenv()

# ------------------------------------------------------------------
# Cross-platform SQLite setup
# The instance/ folder (and therefore the database file) is created
# automatically before SQLAlchemy initialises, so the app boots on any
# OS without manual folder creation or .env edits. The default URI is
# derived from basedir, so it resolves to an absolute path on both
# Windows and Linux. DATABASE_URL is optional; override only when a
# fixed location is required.
# ------------------------------------------------------------------
INSTANCE_DIR = os.path.join(basedir, "instance")

try:
    os.makedirs(INSTANCE_DIR, exist_ok=True)
except OSError as exc:
    raise RuntimeError(
        "Cannot create the database directory {}: {}".format(INSTANCE_DIR, exc)
    ) from exc

if not os.access(INSTANCE_DIR, os.W_OK):
    raise RuntimeError(
        "Database directory {} is not writable. Fix its permissions "
        "(e.g. chmod 700 / chown to the app user on EC2).".format(INSTANCE_DIR)
    )

DATABASE_URI_DEFAULT = "sqlite:///" + os.path.join(
    INSTANCE_DIR,
    "database.db",
)


class Config:
    # ---------------- Application ----------------
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

    # ---------------- Database ----------------
    # Defaults to the absolute instance path derived from basedir
    # (portable across Windows and Linux). DATABASE_URL is optional.
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", DATABASE_URI_DEFAULT)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ---------------- Local storage ----------------
    UPLOAD_FOLDER = os.path.join(basedir, "uploads")

    # ---------------- Session / Cookies ----------------
    PERMANENT_SESSION_LIFETIME = int(os.getenv("SESSION_TIMEOUT_SECONDS", "300"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    # Secure cookies behind HTTPS (keep False for localhost)
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

    # ---------------- AWS S3 (environment-driven, never hardcoded) ----------------
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
    AWS_BUCKET_NAME = os.getenv(
        "AWS_BUCKET_NAME",
        "smart-cloud-storage-zero-architecture",
    )

    # ---------------- Storage backend ----------------
    # "auto"  -> S3 when credentials + bucket are set, else local uploads/
    # "s3"    -> always Amazon S3 (falls back to local if not configured)
    # "local" -> always use the local uploads/ folder (demo mode)
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "auto").strip().lower()

    # ---------------- Master Key (AES envelope encryption) ----------------
    # 32 random bytes encoded as 64 hex characters.
    MASTER_KEY = os.getenv("MASTER_KEY", "")

    # ---------------- MFA ----------------
    MFA_REQUIRED = os.getenv("MFA_REQUIRED", "true").lower() == "true"
    OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))
    # Max wrong OTP attempts before a new OTP is issued + sent.
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "3"))
    # Max manual OTP resends before the user must wait / login again.
    OTP_MAX_RESENDS = int(os.getenv("OTP_MAX_RESENDS", "3"))
    # Account unlock OTP expiry (10 minutes).
    UNLOCK_OTP_TTL_SECONDS = int(os.getenv("UNLOCK_OTP_TTL_SECONDS", "600"))

    # ---------------- Account Lock ----------------
    MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
    LOCK_DURATION_MINUTES = int(os.getenv("LOCK_DURATION_MINUTES", "30"))

    # ---------------- File Fragmentation ----------------
    FRAGMENT_SIZE_BYTES = int(os.getenv("FRAGMENT_SIZE_BYTES", str(4 * 1024 * 1024)))

    # ---------------- Email / SMTP ----------------
    MAIL_ENABLED = os.getenv("MAIL_ENABLED", "false").lower() == "true"
    MAIL_SERVER = os.getenv("MAIL_SERVER", "")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@smartcloud.local")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
    ADMIN_EMAILS = [
        email.strip().lower()
        for email in os.getenv("ADMIN_EMAILS", "").split(",")
        if email.strip()
    ]

    # ---------------- Rate Limiting ----------------
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "true").lower() == "true"

    # ---------------- Upload Limits ----------------
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))
