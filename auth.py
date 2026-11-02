"""
================================================================
AUTH BLUEPRINT
================================================================
- Registration with first-time email OTP verification
- Password-only login for LOW risk accounts
- Email OTP verification for MEDIUM risk accounts
- Login blocked + account locked for HIGH risk accounts
- Account lock after MAX_FAILED_ATTEMPTS failed logins
  (locked_until = 30 minutes by default)
- Account unlock via a separate unlock OTP (10 minute validity)
- OTP attempt limit (max 3) and resend limit (max 3)
================================================================
"""

from datetime import datetime

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)

import audit
from config import Config
from email_service import (
    OTP_SEND_FAILURE,
    alert_account_locked,
    alert_high_risk,
    alert_high_risk_operation,
    alert_multiple_failed,
    alert_multiple_otp_failures,
    alert_new_device,
    alert_password_changed,
    alert_repeated_password_change_attempts,
    deliver_otp,
    dev_otp_visible,
    otp_message,
    send_otp,
    send_password_change_otp,
    send_unlock_otp,
)
from models import User, bcrypt, db
from security import (
    RISK_HIGH_THRESHOLD,
    RISK_MEDIUM_THRESHOLD,
    generate_otp,
    get_browser,
    get_client_ip,
    get_device,
    get_location,
    get_os,
    get_risk_level,
    is_account_locked,
    issue_stepup_otp,
    limiter,
    lock_account,
    promote_admin_if_needed,
    sensitive_operation_blocked,
)

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_ATTEMPTS = Config.MAX_FAILED_ATTEMPTS


def _utc_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def _set_lock(user):
    """Locks the account until locked_until (30 minutes by default)."""
    lock_account(user)


def _clear_lock(user):
    user.account_locked = False
    user.lock_time = None
    user.locked_until = None
    user.failed_attempts = 0


def _complete_login(user, email):
    """Registers the session + audit + new-device alert for a login."""
    prev_ip = user.last_login_ip
    prev_device = user.last_device

    user.failed_attempts = 0
    user.risk_score = max(0, user.risk_score - 5)
    user.login_count += 1
    user.last_login = datetime.utcnow()
    user.last_login_ip = get_client_ip()
    user.last_device = get_device()
    db.session.commit()

    session.clear()
    session.permanent = True
    session["email"] = email
    session["mfa_verified"] = True
    session["auth_version"] = user.auth_version or 0
    now_ts = datetime.utcnow().timestamp()
    session["login_time"] = now_ts
    session["last_activity"] = now_ts

    audit.log_activity(
        email=email,
        action="Login Successful",
        status="Success",
    )

    is_new_device = (
        prev_device is None
        or prev_device != user.last_device
        or (prev_ip is not None and prev_ip != user.last_login_ip)
    )
    if is_new_device:
        alert_new_device(
            email,
            user.last_device,
            get_browser(),
            get_os(),
            user.last_login_ip,
            user.last_login.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )


def _issue_otp(user, intent):
    """Stores a fresh login/register OTP and records pending intent."""
    otp = generate_otp()
    user.set_otp(otp, Config.OTP_TTL_SECONDS)
    user.otp_created_at = datetime.utcnow()
    user.otp_attempts = 0
    user.otp_resends = 0
    db.session.commit()

    session["pending_mfa"] = user.email
    session["pending_intent"] = intent
    if dev_otp_visible():
        session["pending_otp_plaintext"] = otp
    return otp


def _issue_unlock_otp(user):
    """Stores a fresh account-unlock OTP (10 minute validity)."""
    otp = generate_otp()
    user.set_unlock_otp(otp, Config.UNLOCK_OTP_TTL_SECONDS)
    db.session.commit()

    session["pending_mfa"] = user.email
    session["pending_intent"] = "unlock"
    if dev_otp_visible():
        session["pending_unlock_otp_plaintext"] = otp
    return otp


# ============================================================
# REGISTER (with first-time email OTP verification)
# ============================================================

@auth_bp.post("/register")
@limiter.limit("3 per minute")
def register():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "message": "Email and Password are required."
        }), 400

    if len(password) < 8:
        return jsonify({
            "message": "Password must be at least 8 characters."
        }), 400

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        audit.log_activity(
            email=email,
            action="Registration Failed",
            status="Failed",
        )
        return jsonify({
            "message": "User already exists."
        }), 409

    user = User(
        email=email,
        risk_score=0,
        failed_attempts=0,
        account_locked=False,
        lock_time=None,
        mfa_enabled=True,
        email_verified=False,
        is_admin=email in Config.ADMIN_EMAILS,
        login_count=0,
        last_login=None,
    )

    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    audit.log_activity(
        email=email,
        action="User Registered",
        status="Success",
    )

    # First-time verification: OTP sent to the email.
    otp = _issue_otp(user, "register")
    if not deliver_otp(send_otp, email, otp):
        audit.log_activity(
            email=email,
            action="OTP Delivery Failed (Registration)",
            status="Failed",
        )
        return jsonify({
            "message": OTP_SEND_FAILURE,
        }), 500

    audit.log_activity(
        email=email,
        action="OTP Sent (Registration)",
        status="Success",
    )

    return jsonify({
        "message": otp_message(
            "Registration successful. An OTP was sent to your "
            "email for first-time verification."
        ),
        "email": email,
        "verification_required": True,
    })


# ============================================================
# LOGIN
#   LOW    -> password only
#   MEDIUM -> password + email OTP
#   HIGH   -> blocked + locked + alert
# ============================================================

@auth_bp.post("/login")
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "message": "Email and Password are required."
        }), 400

    user = User.query.filter_by(email=email).first()

    # ---------------- User not found ----------------
    if not user:
        audit.log_activity(
            email=email,
            action="Login Failed",
            status="Failed",
        )
        return jsonify({
            "message": "User not found."
        }), 404

    # ---------------- Email must be verified first ----------------
    if not user.email_verified:
        otp = _issue_otp(user, "register")
        if not deliver_otp(send_otp, email, otp):
            return jsonify({
                "message": OTP_SEND_FAILURE,
            }), 500
        audit.log_activity(
            email=email,
            action="OTP Sent (Verification)",
            status="Success",
        )
        return jsonify({
            "message": otp_message(
                "Your email is not verified yet. "
                "An OTP was sent for verification."
            ),
            "email": email,
            "verification_required": True,
        }), 403

    # ---------------- Locked account -> unlock via OTP ----------------
    if is_account_locked(user):
        otp = _issue_unlock_otp(user)
        if not deliver_otp(send_unlock_otp, email, otp):
            return jsonify({
                "message": OTP_SEND_FAILURE,
            }), 500
        audit.log_activity(
            email=email,
            action="Unlock OTP Sent",
            status="Success",
        )
        return jsonify({
            "message": otp_message(
                "Your account is locked. An OTP was sent to unlock it."
            ),
            "email": email,
            "unlock_required": True,
        }), 403

    # ---------------- Password check ----------------
    if not user.check_password(password):
        user.failed_attempts += 1
        user.risk_score += 20
        db.session.commit()

        audit.log_activity(
            email=email,
            action="Wrong Password",
            status="Failed",
        )

        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            _set_lock(user)
            db.session.commit()

            audit.log_activity(
                email=email,
                action="Account Locked",
                status="Blocked",
            )
            alert_account_locked(
                email,
                MAX_FAILED_ATTEMPTS,
                user.locked_until.strftime("%Y-%m-%d %H:%M:%S UTC"),
            )

            otp = _issue_unlock_otp(user)
            if not deliver_otp(send_unlock_otp, email, otp):
                return jsonify({
                    "message": OTP_SEND_FAILURE,
                }), 500

            return jsonify({
                "message": otp_message(
                    f"Account locked after {MAX_FAILED_ATTEMPTS} "
                    "failed attempts. An OTP was sent to unlock it."
                ),
                "email": email,
                "unlock_required": True,
            }), 403

        if user.failed_attempts >= 2:
            alert_multiple_failed(email, user.failed_attempts)

        return jsonify({
            "message": "Wrong Password",
            "remaining_attempts":
                MAX_FAILED_ATTEMPTS - user.failed_attempts,
            "risk_score": user.risk_score,
            "risk_level": get_risk_level(user.risk_score),
        }), 401

    # ---------------- Password correct: risk based decision ----------------
    if user.risk_score >= RISK_HIGH_THRESHOLD:
        # HIGH risk -> block login, lock account, alert, OTP unlock.
        _set_lock(user)
        db.session.commit()

        audit.log_activity(
            email=email,
            action="High Risk Login Blocked",
            status="Blocked",
        )
        alert_high_risk(
            email,
            get_client_ip(),
            get_browser(),
            get_os(),
            get_location(),
            _utc_str(),
            user.risk_score,
        )

        otp = _issue_unlock_otp(user)
        if not deliver_otp(send_unlock_otp, email, otp):
            return jsonify({
                "message": OTP_SEND_FAILURE,
            }), 500

        return jsonify({
            "message": otp_message(
                "Login blocked due to high risk. The account was locked. "
                "An OTP was sent to unlock it."
            ),
            "email": email,
            "unlock_required": True,
        }), 403

    if user.risk_score >= RISK_MEDIUM_THRESHOLD:
        # MEDIUM risk -> require email OTP to complete the login.
        otp = _issue_otp(user, "login")
        if not deliver_otp(send_otp, email, otp):
            return jsonify({
                "message": OTP_SEND_FAILURE,
            }), 500

        audit.log_activity(
            email=email,
            action="Login OTP Sent",
            status="Success",
        )

        return jsonify({
            "message": otp_message(
                "For your security, an OTP was sent to verify this login."
            ),
            "email": email,
            "otp_required": True,
        }), 202

    promote_admin_if_needed(user)
    _complete_login(user, email)

    return jsonify({
        "message": "Login Successful",
        "email": email,
        "risk_score": user.risk_score,
        "risk_level": get_risk_level(user.risk_score),
        "login_count": user.login_count,
    })


# ============================================================
# UNLOCK ACCOUNT (explicit endpoint for the login page)
# ============================================================

@auth_bp.post("/unlock")
@limiter.limit("5 per minute")
def unlock_account():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({
            "message": "Email is required."
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            "message": "User not found."
        }), 404

    if not is_account_locked(user):
        return jsonify({
            "message": "Your account is not locked."
        }), 400

    otp = _issue_unlock_otp(user)
    send_unlock_otp(email, otp)

    audit.log_activity(
        email=email,
        action="Unlock OTP Sent",
        status="Success",
    )

    return jsonify({
        "message": "An OTP was sent to your email to unlock your account.",
        "email": email,
        "unlock_required": True,
    })


# ============================================================
# OTP VERIFICATION PAGE
# ============================================================

@auth_bp.get("/verify_otp")
def verify_otp_page():
    email = request.args.get("email") or session.get("pending_mfa", "")
    mode = (
        request.args.get("mode")
        or session.get("pending_intent", "login")
    )
    ttl = (
        Config.UNLOCK_OTP_TTL_SECONDS
        if mode == "unlock"
        else Config.OTP_TTL_SECONDS
    )
    return render_template(
        "verify_otp.html",
        email=email,
        mode=mode,
        otp_ttl_seconds=ttl,
        dev_mode=Config.DEV_MODE,
    )


# ============================================================
# VERIFY OTP (register / login / unlock)
# ============================================================

@auth_bp.post("/verify_otp")
@limiter.limit("5 per minute")
def verify_otp():
    data = request.get_json(silent=True) or {}

    email = (
        data.get("email")
        or session.get("pending_mfa", "")
    ).strip().lower()
    otp = str(data.get("otp", "")).strip()
    mode = data.get("mode") or session.get("pending_intent", "login")

    if session.get("pending_mfa") != email:
        return jsonify({
            "message": "No OTP request found. Please login again."
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            "message": "User not found."
        }), 404

    # ---------------- UNLOCK mode ----------------
    if mode == "unlock":
        if user.unlock_otp_expired():
            audit.log_activity(
                email=email,
                action="Unlock OTP Expired",
                status="Failed",
            )
            otp = _issue_unlock_otp(user)
            send_unlock_otp(email, otp)
            return jsonify({
                "message": (
                    "The unlock OTP expired. A new one was sent."
                ),
                "email": email,
            }), 401

        if not user.verify_unlock_otp(otp):
            user.unlock_otp_attempts = (user.unlock_otp_attempts or 0) + 1
            db.session.commit()
            audit.log_activity(
                email=email,
                action="Unlock OTP Verification Failed",
                status="Failed",
            )
            if user.unlock_otp_attempts >= Config.OTP_MAX_ATTEMPTS:
                otp = _issue_unlock_otp(user)
                send_unlock_otp(email, otp)
                alert_multiple_otp_failures(email, "account unlock")
                return jsonify({
                    "message": (
                        "Too many invalid attempts. A new unlock OTP was sent to "
                        "your email."
                    ),
                    "email": email,
                }), 401
            return jsonify({
                "message": "Invalid or expired OTP.",
                "remaining_attempts":
                    Config.OTP_MAX_ATTEMPTS - user.unlock_otp_attempts,
            }), 401

        user.clear_unlock_otp()
        _clear_lock(user)
        user.risk_score = max(0, user.risk_score - 20)
        db.session.commit()

        audit.log_activity(
            email=email,
            action="Account Unlocked via OTP",
            status="Success",
        )

        _complete_login(user, email)

        return jsonify({
            "message": "Account unlocked. Welcome back!",
            "email": email,
        })

    # ---------------- REGISTER / LOGIN modes ----------------
    if user.otp_expired():
        audit.log_activity(
            email=email,
            action="OTP Expired",
            status="Failed",
        )
        intent = session.get("pending_intent", mode)
        otp = _issue_otp(user, intent)
        send_otp(email, otp)
        return jsonify({
            "message": "The OTP expired. A new one was sent.",
            "email": email,
        }), 401

    if not user.verify_otp(otp):
        user.otp_attempts = (user.otp_attempts or 0) + 1
        db.session.commit()

        audit.log_activity(
            email=email,
            action="OTP Verification Failed",
            status="Failed",
        )

        if user.otp_attempts >= Config.OTP_MAX_ATTEMPTS:
            intent = session.get("pending_intent", mode)
            otp = _issue_otp(user, intent)
            send_otp(email, otp)
            return jsonify({
                "message": (
                    "Too many invalid attempts. A new OTP was sent to "
                    "your email."
                ),
                "email": email,
            }), 401

        return jsonify({
            "message": "Invalid or expired OTP.",
            "remaining_attempts":
                Config.OTP_MAX_ATTEMPTS - user.otp_attempts,
        }), 401

    # ---------------- OTP verified ----------------
    user.clear_otp()

    if mode == "register":
        user.email_verified = True
        audit.log_activity(
            email=email,
            action="Email Verified",
            status="Success",
        )
    else:
        audit.log_activity(
            email=email,
            action="OTP Verified",
            status="Success",
        )

    _clear_lock(user)
    user.risk_score = max(0, user.risk_score - 20)
    db.session.commit()

    _complete_login(user, email)

    return jsonify({
        "message": "Verification successful. Welcome!",
        "email": email,
    })


# ============================================================
# RESEND OTP (max OTP_MAX_RESENDS resends)
# ============================================================

@auth_bp.post("/resend_otp")
@limiter.limit("3 per minute")
def resend_otp():
    data = request.get_json(silent=True) or {}

    email = (
        data.get("email")
        or session.get("pending_mfa", "")
    ).strip().lower()

    if session.get("pending_mfa") != email:
        return jsonify({
            "message": "No OTP request found. Please login again."
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            "message": "User not found."
        }), 404

    intent = session.get("pending_intent", "login")

    if intent == "unlock":
        if (user.unlock_otp_resends or 0) >= Config.OTP_MAX_RESENDS:
            audit.log_activity(
                email=email,
                action="Unlock OTP Resend Blocked (Limit Reached)",
                status="Failed",
            )
            return jsonify({
                "message": (
                    "Maximum unlock OTP resend attempts reached. Please wait or contact support."
                )
            }), 429

        otp = generate_otp()
        user.set_unlock_otp(otp, Config.UNLOCK_OTP_TTL_SECONDS)
        user.unlock_otp_resends = (user.unlock_otp_resends or 0) + 1
        db.session.commit()
        if Config.DEV_MODE:
            session["pending_unlock_otp_plaintext"] = otp
        send_unlock_otp(email, otp)
        action = "Unlock OTP Resent"
    else:
        if (user.otp_resends or 0) >= Config.OTP_MAX_RESENDS:
            audit.log_activity(
                email=email,
                action="OTP Resend Blocked (Limit Reached)",
                status="Failed",
            )
            return jsonify({
                "message": (
                    "Maximum resend attempts reached. Please login again "
                    "to request a fresh OTP."
                )
            }), 429

        otp = generate_otp()
        user.set_otp(otp, Config.OTP_TTL_SECONDS)
        user.otp_created_at = datetime.utcnow()
        user.otp_attempts = 0
        user.otp_resends = (user.otp_resends or 0) + 1
        db.session.commit()

        if Config.DEV_MODE:
            session["pending_otp_plaintext"] = otp
        send_otp(email, otp)
        action = "OTP Resent"

    audit.log_activity(
        email=email,
        action=action,
        status="Success",
    )

    return jsonify({
        "message": "A new OTP has been sent to your email.",
        "otp_ttl_seconds": (
            Config.UNLOCK_OTP_TTL_SECONDS
            if intent == "unlock"
            else Config.OTP_TTL_SECONDS
        ),
    })


# ============================================================
# DEV OTP (local development only)
# ============================================================

@auth_bp.get("/dev/otp")
def dev_otp():
    if not Config.DEV_MODE:
        return jsonify({"message": "Not available."}), 404
    return jsonify({
        "otp": session.get("pending_otp_plaintext", ""),
        "unlock_otp": session.get("pending_unlock_otp_plaintext", ""),
        "stepup_otp": session.get("stepup_otp_plaintext", ""),
    })


# ============================================================
# CHANGE PASSWORD (Step-Up OTP flow)
#   Step 1: validate old password + issue Password-Change OTP
#   Step 2: verify OTP -> apply new password -> logout ALL sessions
# ============================================================

@auth_bp.get("/change_password")
def change_password_page():
    if "email" not in session:
        return redirect("/")
    return render_template("change_password.html")


@auth_bp.post("/change_password")
@limiter.limit("5 per minute")
def change_password():
    if "email" not in session:
        return jsonify({
            "message": "Session Expired. Please login again."
        }), 401

    email = session["email"]
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found."}), 404

    data = request.get_json(silent=True) or {}

    old_password = data.get("old_password")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not old_password or not new_password or not confirm_password:
        return jsonify({
            "message": "Current, new and confirm passwords are required."
        }), 400

    if new_password != confirm_password:
        return jsonify({
            "message": "New passwords do not match."
        }), 400

    if len(new_password) < 8:
        return jsonify({
            "message": "New password must be at least 8 characters."
        }), 400

    if not user.check_password(old_password):
        audit.log_activity(
            email=email,
            action="Password Change Failed",
            status="Failed",
        )
        return jsonify({
            "message": "Current password is incorrect."
        }), 401

    if user.check_password(new_password):
        return jsonify({
            "message": (
                "New password must be different from the current one."
            )
        }), 400

    # ---------------- Risk gate ----------------
    blocked, reason = sensitive_operation_blocked(user)
    if blocked:
        lock_account(user)
        db.session.commit()
        audit.log_activity(
            email=email,
            action="High Risk Password Change Blocked",
            status="Blocked",
        )
        alert_high_risk_operation(
            email,
            "password change",
            None,
            user.risk_score,
        )
        return jsonify({
            "message": reason,
            "risk_score": user.risk_score,
            "risk_level": get_risk_level(user.risk_score),
        }), 403

    # ---------------- Issue Password-Change OTP ----------------
    otp = issue_stepup_otp(user, "password")
    session["pending_stepup"] = {
        "intent": "password",
        "email": email,
    }
    # Store only the irreversible bcrypt hash of the new password.
    session["pending_new_password_hash"] = (
        bcrypt.generate_password_hash(new_password).decode("utf-8")
    )
    if Config.DEV_MODE:
        session["stepup_otp_plaintext"] = otp
    session.modified = True

    send_password_change_otp(email, otp)

    audit.log_activity(
        email=email,
        action="Password Change OTP Sent",
        status="Success",
    )

    return jsonify({
        "message": (
            "An OTP was sent to your email to verify the password change."
        ),
        "password_otp_required": True,
        "email": email,
        "otp_ttl_seconds": Config.OTP_TTL_SECONDS,
    }), 202


@auth_bp.post("/verify_password_otp")
@limiter.limit("5 per minute")
def verify_password_otp():
    data = request.get_json(silent=True) or {}

    email = session.get("email", "")
    pending = session.get("pending_stepup") or {}
    intent = data.get("intent") or pending.get("intent", "")

    if intent != "password" or pending.get("intent") != "password":
        return jsonify({
            "message": "No pending password change found."
        }), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({
            "message": "User not found."
        }), 404

    otp = str(data.get("otp", "")).strip()

    # ---------------- Expired OTP ----------------
    if user.stepup_otp_expired("password"):
        otp_new = issue_stepup_otp(user, "password")
        if Config.DEV_MODE:
            session["stepup_otp_plaintext"] = otp_new
        session.modified = True
        send_password_change_otp(email, otp_new)
        audit.log_activity(
            email=email,
            action="Password Change OTP Expired",
            status="Failed",
        )
        return jsonify({
            "message": "The OTP expired. A new one was sent.",
            "email": email,
        }), 401

    # ---------------- Wrong OTP ----------------
    if not user.verify_stepup_otp("password", otp):
        user.increment_stepup_otp_attempts("password")
        db.session.commit()
        attempts = user.stepup_otp_attempts("password")
        audit.log_activity(
            email=email,
            action="Password Change OTP Verification Failed",
            status="Failed",
        )
        if attempts >= Config.OTP_MAX_ATTEMPTS:
            otp_new = issue_stepup_otp(user, "password")
            if Config.DEV_MODE:
                session["stepup_otp_plaintext"] = otp_new
            session.modified = True
            send_password_change_otp(email, otp_new)
            alert_multiple_otp_failures(email, "password change")
            return jsonify({
                "message": (
                    "Too many invalid attempts. A new OTP was sent to "
                    "your email."
                ),
                "email": email,
            }), 401
        return jsonify({
            "message": "Invalid or expired OTP.",
            "remaining_attempts":
                Config.OTP_MAX_ATTEMPTS - attempts,
        }), 401

    # ---------------- OTP verified: apply the password change ----------------
    new_hash = session.pop("pending_new_password_hash", None)
    session.pop("pending_stepup", None)
    session.modified = True

    if not new_hash:
        return jsonify({
            "message": "Session expired. Please start again."
        }), 400

    user.clear_stepup_otp("password")
    user.password = new_hash
    user.password_changed_at = datetime.utcnow()
    user.bump_auth_version()
    db.session.commit()

    audit.log_activity(
        email=email,
        action="Password Change OTP Verified",
        status="Success",
    )
    audit.log_activity(
        email=email,
        action="Password Changed",
        status="Success",
    )
    alert_password_changed(
        email,
        get_client_ip(),
        _utc_str(),
        get_browser(),
        get_os(),
    )

    # Log out ALL active sessions (current one included).
    session.clear()

    return jsonify({
        "message": (
            "Password changed successfully. "
            "Please login with your new password."
        ),
        "session_invalidated": True,
    })


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.get("/logout")
def logout():
    if "email" in session:
        email = session["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            user.last_logout = datetime.utcnow()
            user.bump_auth_version()
            db.session.commit()
        audit.log_activity(
            email=email,
            action="Logout",
            status="Success",
        )

    session.clear()
    return redirect("/")
