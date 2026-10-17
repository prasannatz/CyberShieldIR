
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(150), nullable=False)
    incident_type = db.Column(db.String(50), nullable=False)
    industry = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Detected"
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    actions = db.relationship(
        "ResponseAction",
        backref="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )


class ResponseAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incident.id"),
        nullable=False
    )

    action = db.Column(db.Text, nullable=False)
    
    previous_hash = db.Column(db.String(64), nullable=True)
    entry_hash = db.Column(db.String(64), nullable=True, unique=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

class ResponseChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incident.id"),
        nullable=False
    )

    task = db.Column(db.String(300), nullable=False)

    completed = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    incident = db.relationship(
        "Incident",
        backref=db.backref(
            "checklist_items",
            lazy=True,
            cascade="all, delete-orphan"
        )
    )
