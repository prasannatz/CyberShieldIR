
from pathlib import Path
from flask import send_file
from incident_report import build_incident_pdf
from audit_log import record_action, verify_audit_log
from models import ResponseChecklistItem
from checklist_playbooks import get_checklist

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort
)
from models import db, Incident, ResponseAction
from response_playbooks import get_recommendations


app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-key-change-before-deployment"

BASE_DIR = Path(__file__).resolve().parent
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + str(BASE_DIR / "cybershield.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

ALLOWED_TYPES = {
    "Phishing", "Ransomware", "Unauthorized Access",
    "Data Breach", "Malware", "Suspicious Transaction",
    "Denial of Service", "Other"
}
ALLOWED_INDUSTRIES = {"Corporate IT", "Finance"}
ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}

STATUSES = [
    "Detected",
    "Contained",
    "Eradicated",
    "Recovery",
    "Resolved"
]


with app.app_context():
    db.create_all()



@app.route("/")
def home():
    # Read search and filter values from the URL
    search_text = request.args.get("q", "").strip()
    selected_type = request.args.get("incident_type", "")
    selected_severity = request.args.get("severity", "")
    selected_status = request.args.get("status", "")

    # Start with all incidents
    query = Incident.query

    # Search by incident title
    if search_text:
        query = query.filter(Incident.title.ilike(f"%{search_text}%"))

    # Apply filters only when the values are valid
    if selected_type in ALLOWED_TYPES:
        query = query.filter(Incident.incident_type == selected_type)
    else:
        selected_type = ""

    if selected_severity in ALLOWED_SEVERITIES:
        query = query.filter(Incident.severity == selected_severity)
    else:
        selected_severity = ""

    if selected_status in STATUSES:
        query = query.filter(Incident.status == selected_status)
    else:
        selected_status = ""

    # Results matching the selected filters
    incidents = query.order_by(Incident.id.desc()).all()

    # Dashboard totals remain based on ALL incidents
    total = Incident.query.count()
    open_count = Incident.query.filter(
        Incident.status != "Resolved"
    ).count()
    critical_count = Incident.query.filter(
        Incident.severity == "Critical",
        Incident.status != "Resolved"
    ).count()
    resolved_count = Incident.query.filter_by(
        status="Resolved"
    ).count()

    return render_template(
        "index.html",
        incidents=incidents,
        total=total,
        open_count=open_count,
        critical_count=critical_count,
        resolved_count=resolved_count,
        search_text=search_text,
        selected_type=selected_type,
        selected_severity=selected_severity,
        selected_status=selected_status,
        incident_types=sorted(ALLOWED_TYPES),
        severity_options=["Low", "Medium", "High", "Critical"],
        status_options=STATUSES
    )



@app.route("/incidents/new", methods=["GET", "POST"])
def new_incident():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        incident_type = request.form.get("incident_type", "")
        industry = request.form.get("industry", "")
        severity = request.form.get("severity", "")
        description = request.form.get("description", "").strip()

        if not title or len(title) > 150:
            flash("Enter a title of 1 to 150 characters.", "error")
            return render_template("new.html"), 400

        if not description or len(description) > 5000:
            flash("Enter a description of 1 to 5000 characters.", "error")
            return render_template("new.html"), 400

        if incident_type not in ALLOWED_TYPES:
            flash("Select a valid incident type.", "error")
            return render_template("new.html"), 400

        if industry not in ALLOWED_INDUSTRIES:
            flash("Select a valid industry.", "error")
            return render_template("new.html"), 400

        if severity not in ALLOWED_SEVERITIES:
            flash("Select a valid severity.", "error")
            return render_template("new.html"), 400

        incident = Incident(
            title=title,
            incident_type=incident_type,
            industry=industry,
            severity=severity,
            description=description,
            status="Detected"
        )

        db.session.add(incident)
        db.session.flush()

        db.session.commit()
        
        record_action(
            incident.id,
            "Incident reported. Initial status: Detected."
        )

        flash(f"Incident #{incident.id} was recorded successfully.")
        return redirect(url_for("home"))

    return render_template("new.html")



@app.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    incident = db.session.get(Incident, incident_id)

    if incident is None:
        abort(404)

    recommendations = get_recommendations(
        incident.incident_type,
        incident.severity
    )
    
    if not incident.checklist_items:
        tasks = get_checklist(
            incident.incident_type,
            incident.severity
        )
        
        for task in tasks:
            db.session.add(
                ResponseChecklistItem(
                    incident_id=incident.id,
                    task=task
                )
            )
        
        db.session.commit()
        
    return render_template(
        "incident_detail.html",
        incident=incident,
        statuses=STATUSES,
        recommendations=recommendations,
        checklist_items=incident.checklist_items,
    )


@app.route(
    "/incidents/<int:incident_id>/status",
    methods=["POST"]
)
def update_status(incident_id):
    incident = db.session.get(Incident, incident_id)

    if incident is None:
        abort(404)

    new_status = request.form.get("status", "")
    note = request.form.get("note", "").strip()

    if new_status not in STATUSES:
        flash("Select a valid response status.", "error")
        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    if not note or len(note) > 2000:
        flash("Enter a note of 1 to 2000 characters.", "error")
        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    old_status = incident.status

    if old_status != new_status:
        incident.status = new_status
        log_text = (
            f"Status changed from {old_status} to {new_status}. "
            f"Recorded action: {note}"
        )
    else:
        log_text = (
            f"Status remains {old_status}. "
            f"Recorded action: {note}"
        )
    
    record_action(incident.id, log_text)

    flash("Response status and history updated successfully.")
    return redirect(
        url_for("incident_detail", incident_id=incident_id)
    )


@app.route(
    "/incidents/<int:incident_id>/actions",
    methods=["POST"]
)
def add_action(incident_id):
    incident = db.session.get(Incident, incident_id)

    if incident is None:
        abort(404)

    action_text = request.form.get("action", "").strip()

    if not action_text or len(action_text) > 2000:
        flash("Enter an action of 1 to 2000 characters.", "error")
        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    record_action(incident.id, action_text)

    flash("Response action recorded successfully.")
    return redirect(
        url_for("incident_detail", incident_id=incident_id)
    )


@app.route("/incidents/<int:incident_id>/report")
def download_incident_report(incident_id):
    incident = db.session.get(Incident, incident_id)

    if incident is None:
        abort(404)

    recommendations = get_recommendations(
        incident.incident_type,
        incident.severity
    )

    pdf_buffer = build_incident_pdf(incident, recommendations)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"CyberShield_IR_Incident_{incident.id}.pdf"
    )
    

@app.route("/analytics")
def analytics():
    import base64
    from io import BytesIO
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    
    def make_chart(labels, values, title, chart_type="bar"):
        import textwrap
        from matplotlib.ticker import MaxNLocator

        # CyberShield Midnight palette: navy surfaces, cyan highlights, soft labels.
        bg = "#0d2037"
        text_color = "#dcecff"
        muted_color = "#91a8c3"
        grid_color = "#203b57"
        palette = ["#39d5f2", "#4f8cff", "#36d6a0", "#ffbf5b",
                   "#ff7188", "#a78bfa", "#50c9b8", "#f08bc4"]

        if chart_type == "pie":
            pairs = [(label, value) for label, value in zip(labels, values) if value > 0]
            labels = [pair[0] for pair in pairs]
            values = [pair[1] for pair in pairs]
            fig, ax = plt.subplots(figsize=(7.2, 4.6), facecolor=bg)
            ax.set_facecolor(bg)
            if values:
                wedges, texts, autotexts = ax.pie(
                    values,
                    labels=None,
                    autopct=lambda pct: f"{pct:.0f}%" if pct >= 5 else "",
                    startangle=90,
                    counterclock=False,
                    pctdistance=0.7,
                    colors=palette[:len(values)],
                    wedgeprops={"width": 0.38, "edgecolor": bg, "linewidth": 3},
                    textprops={"color": text_color, "fontsize": 10, "fontweight": "bold"}
                )
                for autotext in autotexts:
                    autotext.set_color("#071426")
                    autotext.set_fontweight("bold")
                    autotext.set_fontsize(9)
                ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(0.95, 0.5),
                          frameon=False, labelcolor=muted_color, fontsize=9)
                ax.text(0, 0.04, str(sum(values)), ha="center", va="center",
                        color=text_color, fontsize=23, fontweight="bold")
                ax.text(0, -0.19, "INCIDENTS", ha="center", va="center",
                        color=muted_color, fontsize=7, fontweight="bold")
                ax.axis("equal")
            else:
                ax.text(0.5, 0.5, "No incidents recorded yet", ha="center", va="center",
                        color=muted_color, fontsize=11, transform=ax.transAxes)
                ax.axis("off")
        else:
            fig, ax = plt.subplots(figsize=(8.2, 4.5), facecolor=bg)
            ax.set_facecolor(bg)
            wrapped_labels = ["\n".join(textwrap.wrap(str(label), width=14)) for label in labels]
            bars = ax.bar(range(len(values)), values, width=0.58,
                          color=palette[0], edgecolor="none", zorder=3)
            for i, bar in enumerate(bars):
                bar.set_color(palette[i % len(palette)] if chart_type == "status" else palette[0])
                bar.set_alpha(0.92)
                height = bar.get_height()
                ax.annotate(str(int(height)), (bar.get_x() + bar.get_width()/2, height),
                            xytext=(0, 6), textcoords="offset points", ha="center",
                            va="bottom", color=text_color, fontsize=9, fontweight="bold")
            ax.set_xticks(range(len(wrapped_labels)))
            ax.set_xticklabels(wrapped_labels, color=muted_color, fontsize=8.5)
            ax.set_ylabel("Number of incidents", color=muted_color, fontsize=9, labelpad=10)
            ax.tick_params(axis="y", colors=muted_color, labelsize=8, length=0)
            ax.tick_params(axis="x", length=0, pad=9)
            ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
            ax.set_ylim(0, max(values, default=0) * 1.25 + 1)
            ax.grid(axis="y", color=grid_color, linewidth=0.8, alpha=0.8, zorder=0)
            ax.set_axisbelow(True)
            for spine in ax.spines.values():
                spine.set_visible(False)

        fig.suptitle(title, color=text_color, fontsize=12, fontweight="bold", x=0.04,
                     ha="left", y=0.97)
        fig.tight_layout(pad=2.0)
        image_buffer = BytesIO()
        fig.savefig(image_buffer, format="png", dpi=150, bbox_inches="tight",
                    facecolor=bg, edgecolor=bg, transparent=False)
        plt.close(fig)
        image_buffer.seek(0)
        return base64.b64encode(image_buffer.read()).decode("utf-8")

    # Count incidents by severity, including categories with zero incidents
    severity_labels = ["Low", "Medium", "High", "Critical"]
    severity_values = [
        Incident.query.filter_by(severity=value).count()
        for value in severity_labels
    ]

    # Count incidents by type
    type_labels = sorted(ALLOWED_TYPES)
    type_values = [
        Incident.query.filter_by(incident_type=value).count()
        for value in type_labels
    ]

    # Count incidents by response status
    status_labels = STATUSES
    status_values = [
        Incident.query.filter_by(status=value).count()
        for value in status_labels
    ]

    return render_template(
        "analytics.html",
        total=Incident.query.count(),
        open_count=Incident.query.filter(
            Incident.status != "Resolved"
        ).count(),
        resolved_count=Incident.query.filter_by(
            status="Resolved"
        ).count(),
        critical_count=Incident.query.filter(
            Incident.severity == "Critical",
            Incident.status != "Resolved"
        ).count(),
        severity_chart=make_chart(
            severity_labels, severity_values,
            "Incidents by Severity"
        ),
        type_chart=make_chart(
            type_labels, type_values,
            "Incidents by Type", "pie"
        ),
        status_chart=make_chart(
            status_labels, status_values,
            "Incidents by Response Status", "status"
        )
    )


@app.route("/audit")
def audit_page():
    valid, message = verify_audit_log()
    entries = ResponseAction.query.order_by(
        ResponseAction.id.desc()
    ).all()

    return render_template(
        "audit.html",
        valid=valid,
        message=message,
        entries=entries
    )

@app.route(
    "/incidents/<int:incident_id>/checklist/<int:item_id>",
    methods=["POST"]
)
def update_checklist_item(incident_id, item_id):
    incident = db.session.get(Incident, incident_id)

    if incident is None:
        abort(404)

    item = db.session.get(ResponseChecklistItem, item_id)

    if item is None or item.incident_id != incident_id:
        abort(404)

    item.completed = not item.completed

    action_text = (
        f"Checklist task {'completed' if item.completed else 'reopened'}: "
        f"{item.task}"
    )

    try:
        record_action(incident.id, action_text)
    except Exception:
        db.session.rollback()
        app.logger.exception("Checklist update failed")
        flash("Checklist update failed. Please check the application log.")
        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    flash("Checklist progress saved.")
    return redirect(
        url_for("incident_detail", incident_id=incident_id)
    )

if __name__ == "__main__":
    app.run(debug=True)