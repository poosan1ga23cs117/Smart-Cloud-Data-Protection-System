"""Display-only IST conversion for naive-UTC datetime objects."""

from datetime import timedelta, timezone

try:
    from zoneinfo import ZoneInfo
    _IST = ZoneInfo("Asia/Kolkata")
except Exception:
    _IST = timezone(timedelta(hours=5, minutes=30), name="IST")



def to_ist(dt):
    """Convert a naive-UTC datetime to IST for display only.

    - None → empty string (no crash in templates)
    - Already tz-aware (UTC) → convert directly
    - Naive (all existing rows) → assume UTC, then convert
    """
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_IST).strftime("%Y-%m-%d %H:%M:%S.%f IST")
