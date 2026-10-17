
from app import app
from models import db
from audit_log import backfill_audit_hashes

with app.app_context():
    valid, message = backfill_audit_hashes()
    print(message)

    if not valid:
        raise SystemExit("Audit log verification failed.")
