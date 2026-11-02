"""
================================================================
AUDIT MODULE
================================================================
Immutable, hash-chained audit logging.

Every log entry stores:
    previous_hash : SHA-256 of the previous entry in the chain
    current_hash  : SHA-256 of (previous_hash + event details)

Any modification of an existing entry breaks every subsequent
hash, making tampering detectable - a blockchain-style audit trail.
================================================================
"""

import hashlib
from datetime import datetime

from flask import has_request_context, request

from models import AuditLog, db
from security import get_risk_level

GENESIS_HASH = "GENESIS"


import json
import logging

logger = logging.getLogger("audit")

def compute_log_hash(
    previous_hash,
    timestamp,
    email,
    action,
    ip,
    device,
    status,
    filename,
    user_id=None,
    risk_score=0,
):
    """SHA-256 over the canonical event string including user_id and risk_score."""
    canonical = "|".join([
        str(previous_hash),
        str(timestamp),
        str(email),
        str(action),
        str(ip),
        str(device),
        str(status),
        str(filename or ""),
        str(user_id if user_id is not None else ""),
        str(risk_score if risk_score is not None else 0),
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def log_activity(email, action, filename=None, status="Success", user_id=None, risk_score=None):
    """
    Stores an immutable hash-chained audit log entry.
    Returns the created AuditLog object.
    """
    if has_request_context():
        forwarded = request.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            request.remote_addr or "Unknown"
        )
        device = request.headers.get("User-Agent", "Unknown")
    else:
        ip = "Unknown"
        device = "Unknown"

    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = (
        last.current_hash
        if last and last.current_hash
        else GENESIS_HASH
    )

    timestamp = datetime.utcnow()

    user = None
    if risk_score is None:
        risk_score = 0
    risk_level = "Low"
    if email:
        from models import User
        user = User.query.filter_by(email=email).first()
        if user:
            if user_id is None:
                user_id = user.id
            if risk_score == 0:
                risk_score = user.risk_score
            risk_level = get_risk_level(risk_score)

    current_hash = compute_log_hash(
        previous_hash,
        timestamp,
        email,
        action,
        ip,
        device,
        status,
        filename,
        user_id=user_id,
        risk_score=risk_score,
    )

    log = AuditLog(
        user_id=user_id,
        email=email or "anonymous",
        action=action,
        filename=filename,
        ip_address=ip,
        device=device,
        status=status,
        risk_score=risk_score,
        risk_level=risk_level,
        timestamp=timestamp,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )

    db.session.add(log)
    db.session.commit()

    # Optional S3 protected audit archiving
    try:
        archive_audit_record(log)
    except Exception as exc:
        logger.debug("Audit S3 archive notice: %s", exc)

    return log


def archive_audit_record(log):
    """Optionally archives an individual audit record to S3 / local storage."""
    from s3_manager import USE_S3, s3, BUCKET
    record_data = json.dumps({
        "id": log.id,
        "user_id": log.user_id,
        "email": log.email,
        "action": log.action,
        "filename": log.filename,
        "ip_address": log.ip_address,
        "device": log.device,
        "status": log.status,
        "risk_score": log.risk_score,
        "risk_level": log.risk_level,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "previous_hash": log.previous_hash,
        "current_hash": log.current_hash,
    }, indent=2)

    key = f"audit_archive/{log.timestamp.strftime('%Y%m')}/audit_{log.id}_{log.current_hash[:12]}.json"
    if USE_S3 and s3 is not None:
        try:
            s3.put_object(
                Bucket=BUCKET,
                Key=key,
                Body=record_data.encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
        except Exception:
            pass


def verify_chain():
    """
    Verifies the integrity of the whole audit chain.
    Returns (valid: bool, broken_entry_id: int|None).
    """
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    prev = GENESIS_HASH
    for log in logs:
        if log.previous_hash != prev:
            return False, log.id
        recomputed = compute_log_hash(
            prev,
            log.timestamp,
            log.email,
            log.action,
            log.ip_address,
            log.device,
            log.status,
            log.filename,
            user_id=log.user_id,
            risk_score=log.risk_score,
        )
        if recomputed != log.current_hash:
            # Check legacy 8-part hash fallback
            legacy_canonical = "|".join([
                str(prev),
                str(log.timestamp),
                str(log.email),
                str(log.action),
                str(log.ip_address),
                str(log.device),
                str(log.status),
                str(log.filename or ""),
            ])
            if hashlib.sha256(legacy_canonical.encode("utf-8")).hexdigest() != log.current_hash:
                return False, log.id
        prev = log.current_hash
    return True, None

