from flask import Flask

from models import db, Incident, ResponseAction
from audit_log import calculate_hash, verify_audit_log


def add_test_entry(incident_id, action_text, previous_hash):
    entry = ResponseAction(
        incident_id=incident_id,
        action=action_text,
        previous_hash=previous_hash
    )

    db.session.add(entry)
    db.session.flush()
    db.session.refresh(entry)

    entry.entry_hash = calculate_hash(entry, previous_hash)
    db.session.commit()

    return entry


def run_test():
    test_app = Flask("audit_integrity_test")

    test_app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite://",
        SQLALCHEMY_TRACK_MODIFICATIONS=False
    )

    # This app uses a separate in-memory database.
    db.init_app(test_app)

    with test_app.app_context():
        try:
            db.create_all()

            incident = Incident(
                title="Temporary Audit Test",
                incident_type="Other",
                industry="Corporate IT",
                severity="Low",
                description="Temporary test incident"
            )

            db.session.add(incident)
            db.session.commit()

            first = add_test_entry(
                incident.id, "Test action 1", ""
            )

            add_test_entry(
                incident.id, "Test action 2", first.entry_hash
            )

            valid, message = verify_audit_log()
            print("BEFORE TAMPERING:", message)

            assert valid, "Fresh audit chain should be valid."

            # Simulate someone changing an existing audit record.
            first.action = "UNAUTHORIZED MODIFICATION"
            db.session.commit()

            valid, message = verify_audit_log()
            print("AFTER TAMPERING:", message)

            assert not valid, "Tampering was not detected!"

            print("\nPASS: Audit tampering was detected.")

        finally:
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    run_test()