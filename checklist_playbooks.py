
CHECKLISTS = {
    "Phishing": [
        "Preserve the suspicious email and its headers.",
        "Identify affected users and check for credential exposure.",
        "Secure affected accounts and revoke suspicious sessions if needed.",
        "Block confirmed malicious indicators using approved controls.",
        "Check for related phishing messages and affected accounts.",
        "Verify account security and document findings."
    ],
    "Ransomware": [
        "Assess the scope and business impact.",
        "Isolate affected devices using approved procedures.",
        "Preserve relevant logs and forensic evidence.",
        "Identify the entry point and affected systems.",
        "Remove the threat and address the exploited weakness.",
        "Restore from verified clean backups and monitor systems."
    ],
    "Unauthorized Access": [
        "Identify the affected account, system, and access time.",
        "Review authentication logs and suspicious activity.",
        "Secure the account and revoke unauthorized sessions.",
        "Check for privilege escalation and persistence.",
        "Restore legitimate access using approved procedures.",
        "Monitor for repeated unauthorized access."
    ],
    "Data Breach": [
        "Identify potentially exposed data and affected systems.",
        "Preserve logs and evidence.",
        "Limit further unauthorized access.",
        "Assess the scope and type of data exposure.",
        "Escalate through privacy, legal, and regulatory procedures.",
        "Document remediation and verify that exposure has stopped."
    ],
    "Malware": [
        "Identify affected devices and security alerts.",
        "Isolate affected devices if required.",
        "Preserve relevant files and logs.",
        "Investigate the likely entry point and scope.",
        "Remove malware and address the underlying weakness.",
        "Verify system integrity and monitor for reinfection."
    ],
    "Suspicious Transaction": [
        "Record transaction references, times, and alert details.",
        "Escalate to the authorized fraud response team.",
        "Verify the transaction through approved procedures.",
        "Apply holds or restrictions only through authorized controls.",
        "Review related transactions and preserve audit records.",
        "Follow applicable reporting and communication procedures."
    ],
    "Denial of Service": [
        "Confirm service disruption using monitoring data.",
        "Identify affected services and traffic patterns.",
        "Notify the network and infrastructure response teams.",
        "Apply approved traffic mitigation controls.",
        "Verify service restoration.",
        "Monitor for recurrence and document the impact."
    ],
    "Other": [
        "Record the observed activity and affected assets.",
        "Preserve available evidence.",
        "Assess the impact and scope.",
        "Escalate to the appropriate responder.",
        "Apply approved containment and remediation measures.",
        "Verify recovery and document findings."
    ]
}


def get_checklist(incident_type, severity):
    tasks = list(CHECKLISTS.get(incident_type, CHECKLISTS["Other"]))

    if severity in {"High", "Critical"}:
        tasks.insert(
            0,
            "Notify the designated incident lead and assess escalation."
        )

    if severity == "Critical":
        tasks.insert(
            1,
            "Assess urgent business impact and activate the critical-incident procedure if warranted."
        )

    return tasks
