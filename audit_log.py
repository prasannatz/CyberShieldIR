
import hashlib
import json

from models import db, ResponseAction


def calculate_hash(action, previous_hash):
    """Calculate a SHA-256 hash for one audit entry."""
    timestamp = (
        action.created_at.isoformat()
        if action.created_at
        else ""
    )

    record = {
        "id": action.id,
        "incident_id": action.incident_id,
        "action": action.action,
        "created_at": timestamp,
        "previous_hash": previous_hash or ""
    }

    canonical_record = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_record.encode("utf-8")
    ).hexdigest()

def record_action(incident_id, action_text):
    """Create and hash a new response-history entry."""
    valid, message = verify_audit_log()

    if not valid:
        raise ValueError(
            f"Audit log verification failed: {message}"
        )

    latest = ResponseAction.query.order_by(
        ResponseAction.id.desc()
    ).first()

    previous_hash = latest.entry_hash if latest else ""

    entry = ResponseAction(
        incident_id=incident_id,
        action=action_text,
        previous_hash=previous_hash or ""
    )

    db.session.add(entry)
    db.session.flush()

    # Refresh database-generated values before hashing.
    db.session.refresh(entry)

    entry.entry_hash = calculate_hash(entry, previous_hash)
    db.session.commit()

    # Confirm the saved entry verifies.
    db.session.refresh(entry)

    valid, message = verify_audit_log()
    if not valid:
        raise ValueError(message)

    return entry


def verify_audit_log():
    """Verify each entry and its link to the preceding entry."""
    entries = ResponseAction.query.order_by(
        ResponseAction.id.asc()
    ).all()

    expected_previous_hash = ""

    for entry in entries:
        if not entry.entry_hash:
            return False, f"Entry #{entry.id} has no hash."

        stored_previous_hash = entry.previous_hash or ""

        if stored_previous_hash != expected_previous_hash:
            return False, (
                f"Entry #{entry.id} has an invalid previous-hash link."
            )

        expected_hash = calculate_hash(
            entry, expected_previous_hash
        )

        if entry.entry_hash != expected_hash:
            return False, (
                f"Entry #{entry.id} content does not match its hash."
            )

        expected_previous_hash = entry.entry_hash

    return True, f"Verified {len(entries)} audit entries."



def backfill_audit_hashes():
    """Safely initialize a hash chain only for completely unhashed logs."""
    entries = ResponseAction.query.order_by(
        ResponseAction.id.asc()
    ).all()

    if not entries:
        return True, "No audit entries to backfill."

    # Never overwrite an existing chain or a partially hashed log.
    if any(entry.entry_hash or entry.previous_hash for entry in entries):
        return False, (
            "Backfill refused: existing hash data was found. "
            "The audit chain was not modified. Investigate or verify "
            "the current log before considering any repair."
        )

    previous_hash = ""

    try:
        for entry in entries:
            entry.previous_hash = previous_hash
            db.session.flush()
            db.session.refresh(entry)

            entry.entry_hash = calculate_hash(entry, previous_hash)
            previous_hash = entry.entry_hash

        db.session.commit()

    except Exception:
        db.session.rollback()
        raise

    return verify_audit_log()

