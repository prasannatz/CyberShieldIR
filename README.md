# CyberShield IR 🛡️

**A Cyber Incident Response Management System for Corporate IT and Finance**

CyberShield IR is a Python Flask-based micro-project designed to help organizations document, manage, and respond to cybersecurity incidents through a structured incident response workflow.

The project provides a centralized dashboard for tracking incidents, following predefined response playbooks, monitoring incident status, reviewing audit history, and generating reports.

## Features

- **Incident Management:** Create and track cybersecurity incidents.
- **Severity Classification:** Categorize incidents as Low, Medium, High, or Critical.
- **Response Playbooks:** Predefined response guidance for different incident types and severity levels.
- **Response Checklists:** Track response tasks and completion status.
- **Incident History:** Review recorded response actions and status changes.
- **Audit Log Integrity:** SHA-256 hash-chain verification to help identify modifications to recorded audit entries.
- **Analytics Dashboard:** View incident statistics by severity, type, and status.
- **PDF Reports:** Generate incident reports for documentation and review.
- **Database Storage:** Store incident and response data using SQLite.

## Technology Stack

- **Language:** Python
- **Backend:** Flask
- **Database:** SQLite
- **ORM:** SQLAlchemy
- **Frontend:** HTML, CSS, JavaScript, Jinja2
- **Security:** Password hashing where implemented, SHA-256 audit integrity verification
- **Reporting:** PDF report generation

## Project Structure

```text
CyberShieldIR/
├── app.py
├── models.py
├── response_playbooks.py
├── checklist_playbooks.py
├── audit_log.py
├── migrate_audit.py
├── backfill_audit.py
├── incident_report.py
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── new.html
│   ├── incident_detail.html
│   ├── audit.html
│   └── analytics.html
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.10 or a compatible Python version
- Git
- pip

### 1. Clone the repository

```bash
git clone https://github.com/prasannatz/CyberShieldIR.git
cd CyberShieldIR
```

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

Open the local address displayed in the terminal, usually:

`http://127.0.0.1:5000`

## Industry Focus

- Corporate IT security operations
- Financial services and incident documentation
- Cybersecurity incident response workflows

## Security Notes

CyberShield IR is an educational incident response management prototype. It supports incident documentation and response workflows; it does **not** independently detect or automatically contain live cyberattacks.

- Do not commit database files, credentials, secret keys, or environment files.
- Use fictional incident data for demonstrations.
- Configure secret keys securely before deployment.
- Audit integrity verification helps detect changes to recorded entries; it does not guarantee that an attacker cannot alter the application or its entire database.

## Project Objective

To demonstrate how a structured incident response workflow can help an organization document security incidents, prioritize their severity, follow response procedures, maintain an auditable history, and review incident trends.

## Project Status

Academic micro-project — working software prototype.

## License

No license has been specified yet. All rights reserved by default unless a license is added.

## Author

Prasanna Tudu
