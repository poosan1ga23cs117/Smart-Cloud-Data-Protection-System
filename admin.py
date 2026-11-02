"""
================================================================
ADMIN BLUEPRINT
================================================================
Admin dashboard with:
  - overview statistics (users, logs, locked accounts, high risk)
  - all users + search
  - unlock accounts
  - all audit logs + search
  - recent logins / uploads / downloads
================================================================
"""

from datetime import datetime, timedelta

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from sqlalchemy import or_

import audit
from models import AuditLog, User, db
from security import get_risk_level, limiter

admin_bp = Blueprint("admin", __name__)

LOGIN_ACTIONS = [
    "Login Successful",
    "Login Failed",
    "Login Attempt While Locked",
    "OTP Verification Failed",
    "High Risk Login Blocked",
    "Logout",
]


def _require_admin():
    email = session.get("email")
    if not email:
        return None
    user = User.query.filter_by(email=email).first()
    if not user or not user.is_admin:
        audit.log_activity(
            email=email or "anonymous",
            action="Unauthorized Admin Access Blocked",
            filename=request.path if request else "admin",
            status="Blocked",
            user_id=user.id if user else None,
            risk_score=user.risk_score if user else 0,
        )
        return None
    return user



# ============================================================
# ADMIN DASHBOARD
# ============================================================

@admin_bp.get("/admin")
@limiter.limit("60 per minute")
def admin_dashboard():
    admin = _require_admin()
    if not admin:
        return redirect("/")

    total_users = User.query.count()
    total_logs = AuditLog.query.count()
    locked_accounts = User.query.filter_by(
        account_locked=True
    ).count()
    high_risk_users = User.query.filter(
        User.risk_score >= 80
    ).count()

    recent_logins = AuditLog.query.filter(
        AuditLog.action.in_(LOGIN_ACTIONS)
    ).order_by(AuditLog.timestamp.desc()).limit(8).all()

    recent_uploads = AuditLog.query.filter_by(
        action="File Uploaded"
    ).order_by(AuditLog.timestamp.desc()).limit(8).all()

    recent_downloads = AuditLog.query.filter_by(
        action="File Downloaded"
    ).order_by(AuditLog.timestamp.desc()).limit(8).all()

    return render_template(
        "admin_dashboard.html",
        admin=admin,
        total_users=total_users,
        total_logs=total_logs,
        locked_accounts=locked_accounts,
        high_risk_users=high_risk_users,
        recent_logins=recent_logins,
        recent_uploads=recent_uploads,
        recent_downloads=recent_downloads,
    )


# ============================================================
# ADMIN - ALL USERS
# ============================================================

@admin_bp.get("/admin/users")
def admin_users():
    admin = _require_admin()
    if not admin:
        return redirect("/")

    query = request.args.get("q", "").strip()
    base = User.query

    if query:
        base = base.filter(User.email.like(f"%{query}%"))

    users = base.order_by(User.id.asc()).all()

    return render_template(
        "admin_users.html",
        admin=admin,
        users=users,
        search=query,
        get_risk_level=get_risk_level,
    )


# ============================================================
# ADMIN - UNLOCK ACCOUNT
# ============================================================

@admin_bp.post("/admin/unlock/<int:user_id>")
def admin_unlock(user_id):
    admin = _require_admin()
    if not admin:
        return jsonify({
            "message": "Access Forbidden: Administrator role required."
        }), 403

    target = User.query.get(user_id)

    if not target:
        return jsonify({
            "message": "User not found."
        }), 404

    target.account_locked = False
    target.failed_attempts = 0
    target.lock_time = None
    target.locked_until = None
    target.clear_unlock_otp()
    target.risk_score = max(0, (target.risk_score or 0) - 20)
    db.session.commit()

    audit.log_activity(
        email=admin.email,
        action="Admin Account Unlock",
        filename=target.email,
        status="Success",
        user_id=admin.id,
        risk_score=admin.risk_score,
    )

    if request.is_json:
        return jsonify({"message": f"Account for {target.email} unlocked successfully."})

    return redirect(f"/admin/users?q={target.email}")


# ============================================================
# ADMIN - ALL AUDIT LOGS
# ============================================================

@admin_bp.get("/admin/logs")
def admin_logs():
    admin = _require_admin()
    if not admin:
        return redirect("/")

    query = request.args.get("q", "").strip()
    base = AuditLog.query

    if query:
        base = base.filter(or_(
            AuditLog.email.like(f"%{query}%"),
            AuditLog.action.like(f"%{query}%"),
            AuditLog.filename.like(f"%{query}%"),
            AuditLog.ip_address.like(f"%{query}%"),
        ))

    logs = base.order_by(AuditLog.timestamp.desc()).limit(500).all()

    return render_template(
        "admin_logs.html",
        admin=admin,
        logs=logs,
        search=query,
    )
