"""
================================================================
SMART CLOUD DATA PROTECTION SYSTEM
Zero Trust Architecture - Application Entry Point
================================================================
app.py stays clean: application factory, blueprint registration,
security middleware, error handlers and page routes.

Feature modules:
  auth.py       - register / OTP verify / password login / unlock
  storage.py    - upload / download / file list (encrypt + fragment)
  admin.py      - admin dashboard, users, unlock, logs
  audit.py      - immutable hash-chained audit logging
  crypto.py     - AES-256-GCM envelope encryption + fragmentation
  security.py   - rate limiting, risk engine, headers, lock logic
  email_service.py - OTP + security alert emails
================================================================
"""

import os
from datetime import datetime, timedelta

import click
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, session

from timezone_utils import to_ist

# Load environment variables (from .env or the process environment)
# BEFORE any configuration module is imported. On EC2 / cloud hosts the
# AWS_* values usually come straight from the platform environment.
load_dotenv()

import audit
from admin import admin_bp
from auth import auth_bp
from config import Config
from models import AuditLog, User, bcrypt, db, migrate_database
from security import (
    apply_security_headers,
    get_risk_level,
    is_account_locked,
    limiter,
)
from storage import storage_bp

audit_log = audit.log_activity


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.secret_key = Config.SECRET_KEY
    app.permanent_session_lifetime = timedelta(
        seconds=Config.PERMANENT_SESSION_LIFETIME
    )

    app.jinja_env.filters["to_ist"] = to_ist

    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # ---------------- Extensions ----------------
    db.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # ---------------- Database + migration ----------------
    with app.app_context():
        db.create_all()
        migrate_database()

    # ---------------- Blueprints ----------------
    app.register_blueprint(auth_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(admin_bp)

    # ---------------- Security headers on every response ----------------
    @app.after_request
    def set_security_headers(response):
        return apply_security_headers(response)

    # ---------------- Refresh session timeout ----------------
    @app.before_request
    def refresh_session():
        if "email" in session:
            now_ts = datetime.utcnow().timestamp()
            last_activity = session.get("last_activity")
            timeout_seconds = Config.PERMANENT_SESSION_LIFETIME

            # Server-side idle session timeout verification
            if last_activity and (now_ts - last_activity > timeout_seconds):
                session.clear()
                from flask import request
                if request.is_json or request.path.startswith("/files") or request.path.startswith("/upload") or request.path.startswith("/download"):
                    return jsonify({"message": "Session Expired. Please login again."}), 401
                return redirect("/")

            # Invalidation guard: auth_version check
            user = User.query.filter_by(
                email=session["email"]
            ).first()
            if not user:
                session.clear()
                return redirect("/")

            current_version = user.auth_version or 0
            if session.get("auth_version") is None:
                session["auth_version"] = current_version
            elif session["auth_version"] != current_version:
                session.clear()
                from flask import request
                if request.is_json or request.path.startswith("/files") or request.path.startswith("/upload") or request.path.startswith("/download"):
                    return jsonify({"message": "Session invalidated. Please login again."}), 401
                return redirect("/")

            session["last_activity"] = now_ts
            session.permanent = True
            session.modified = True

    # ---------------- Error handlers ----------------
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "status": "error",
            "code": 400,
            "message": "Bad Request.",
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "status": "error",
            "code": 401,
            "message": "Unauthorized Access.",
        }), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "status": "error",
            "code": 403,
            "message": "Access Forbidden.",
        }), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "status": "error",
            "code": 404,
            "message": "Resource Not Found.",
        }), 404

    @app.errorhandler(429)
    def ratelimit_handler(error):
        return jsonify({
            "status": "error",
            "code": 429,
            "message": (
                "Too many requests. Please slow down: "
                f"{error.description}"
            ),
        }), 429

    @app.errorhandler(500)
    def internal_server_error(error):
        db.session.rollback()
        return jsonify({
            "status": "error",
            "code": 500,
            "message": "Internal Server Error.",
        }), 500

    # ---------------- Routes ----------------
    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/dashboard/<email>")
    @limiter.limit("60 per minute")
    def dashboard(email):
        if "email" not in session or session["email"] != email:
            return redirect("/")

        user = User.query.filter_by(email=email).first()

        if not user:
            return redirect("/")

        if is_account_locked(user):
            audit_log(email, "Dashboard Access Blocked", status="Blocked")
            return render_template(
                "dashboard.html",
                email=email,
                risk=user.risk_score,
                risk_level=get_risk_level(user.risk_score),
                login_count=user.login_count,
                last_login=user.last_login,
                total_uploads=0,
                total_downloads=0,
                total_files=0,
                recent_logs=[],
                is_admin=user.is_admin,
                locked=True,
            )

        total_uploads = AuditLog.query.filter_by(
            email=email, action="File Uploaded"
        ).count()

        total_downloads = AuditLog.query.filter_by(
            email=email, action="File Downloaded"
        ).count()

        from models import File
        total_files = File.query.filter_by(email=email).count()

        recent_logs = AuditLog.query.filter_by(
            email=email
        ).order_by(AuditLog.timestamp.desc()).limit(5).all()

        audit_log(email, "Dashboard Accessed", status="Success")

        return render_template(
            "dashboard.html",
            email=email,
            risk=user.risk_score,
            risk_level=get_risk_level(user.risk_score),
            login_count=user.login_count,
            last_login=user.last_login,
            total_uploads=total_uploads,
            total_downloads=total_downloads,
            total_files=total_files,
            recent_logs=recent_logs,
            is_admin=user.is_admin,
            locked=False,
        )

    @app.route("/audit_logs")
    def audit_logs():
        if "email" not in session:
            return redirect("/")

        email = session["email"]
        user = User.query.filter_by(email=email).first()

        if not user:
            return redirect("/")

        if is_account_locked(user):
            audit_log(email, "Audit Logs Access Blocked", status="Blocked")
            return redirect(f"/dashboard/{email}")

        logs = AuditLog.query.filter_by(
            email=email
        ).order_by(AuditLog.timestamp.desc()).all()

        audit_log(email, "Viewed Audit Logs", status="Success")

        return render_template(
            "audit_logs.html",
            logs=logs,
            email=email,
            risk=user.risk_score,
            risk_level=get_risk_level(user.risk_score),
            login_count=user.login_count,
            is_admin=user.is_admin,
        )

    @app.route("/health")
    def health():
        total_users = User.query.count()
        total_logs = AuditLog.query.count()

        return jsonify({
            "status": "Healthy",
            "application": "Smart Cloud Data Protection System",
            "zero_trust": True,
            "mfa": "Email OTP (5 minute TTL)",
            "rate_limiting": "IP Based (Flask-Limiter)",
            "risk_based_auth": True,
            "integrity": "SHA-256 + HMAC",
            "audit_chain": "Immutable Hash Chained Logs",
            "session_timeout": "5 Minutes",
            "account_lock": (
                f"{Config.MAX_FAILED_ATTEMPTS} Failed Attempts"
            ),
            "lock_duration": (
                f"{Config.LOCK_DURATION_MINUTES} Minutes"
            ),
            "otp_max_attempts": Config.OTP_MAX_ATTEMPTS,
            "otp_max_resends": Config.OTP_MAX_RESENDS,
            "total_users": total_users,
            "total_audit_logs": total_logs,
            "server_time": datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
        })

    @app.route("/about")
    def about():
        return jsonify({
            "project": "Smart Cloud Data Protection System",
            "architecture": "Zero Trust Architecture",
            "framework": "Flask",
            "database": "SQLite (SQLAlchemy)",
            "cloud_storage": "Amazon S3",
            "encryption": "AES-256-GCM (per-file key + master key wrap)",
            "integrity": "HMAC-SHA256 + SHA-256 verification",
            "authentication": "Session Based + Password",
            "authorization": "Risk Based Authentication + Roles",
            "features": [
                "User Registration",
                "Email OTP First-Time Verification",
                "Risk Based Authentication",
                "Password Only Login (Low Risk)",
                "Email OTP Login Verification (Medium Risk)",
                "IP Rate Limiting",
                "AES-256-GCM Envelope Encryption",
                "Encrypted File Fragmentation",
                "SHA-256 Integrity Verification",
                "Immutable Hash Chained Audit Logs",
                "Amazon S3 Storage",
                "Risk Score Calculation",
                "Account Lock + OTP Unlock",
                "Session Timeout",
                "Audit Logs",
                "IP Tracking",
                "Device Tracking",
                "Email Security Alerts",
                "Admin Dashboard",
                "Security Headers",
                "Secure Cookies",
            ],
        })

    return app


# ============================================================
# CLI COMMAND - promote a user to admin
# ============================================================

@click.command("create-admin")
@click.argument("email")
def create_admin(email):
    """Promote a user to the admin role."""
    app = create_app()
    with app.app_context():
        user = User.query.filter_by(email=email.lower()).first()
        if not user:
            click.echo(f"User {email} not found.")
            return
        user.is_admin = True
        db.session.commit()
        click.echo(f"User {email} is now an admin.")


# ============================================================
# APPLICATION INSTANCE (WSGI entry point)
# ------------------------------------------------------------
# This module-level `app` is the WSGI application object that
# Gunicorn serves via `gunicorn -w 4 -b 0.0.0.0:8000 app:app`.
# It is created exactly once here and reused by every worker,
# so `app.run()` must stay guarded by `__main__` (below).
# ============================================================

app = create_app()
app.cli.add_command(create_admin)


# ============================================================
# START APPLICATION
# ============================================================
#
# Development (direct execution):
#     python app.py
#
# Production (Gunicorn - never executes this block, it only
# imports the module and serves the `app` object above):
#     gunicorn -w 4 -b 0.0.0.0:8000 app:app
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print(" Smart Cloud Data Protection System")
    print(" Zero Trust Architecture Enabled")
    print(" AES-256-GCM + HMAC + Fragmentation")
    print(" Email OTP Verification + Risk Based Auth")
    print(" Session Timeout : 5 Minutes")
    print(f" Account Lock : {Config.MAX_FAILED_ATTEMPTS} Failed Attempts")
    print(f" Lock Duration : {Config.LOCK_DURATION_MINUTES} Minutes")
    print("=" * 60)

    if Config.DEBUG:
        print(" [MODE] Development - debug=True, auto-reloader enabled")
    else:
        print(" [MODE] Production - debug=False")
        print("        Start with Gunicorn:")
        print("        gunicorn -w 4 -b 0.0.0.0:8000 app:app")

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=Config.DEBUG,
    )
