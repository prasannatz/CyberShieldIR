
# response_playbooks.py
# CyberShield IR — severity-aware incident response plans
#
# These are recommended human-led response steps.
# They do not automatically detect attacks or isolate systems.

SEVERITIES = ("Low", "Medium", "High", "Critical")

PLAYBOOKS = {
    "Phishing": {
        "Low": [
            "Preserve the suspicious email and its full headers for review.",
            "Check whether the message contains suspicious links, attachments, or sender details.",
            "Report the email to the security team and warn the recipient not to interact with it.",
            "Record the affected mailbox and document the investigation outcome.",
        ],
        "Medium": [
            "Preserve the email, headers, links, and attachment details as evidence.",
            "Identify recipients and check whether anyone clicked a link or opened an attachment.",
            "Ask the mail administrator to quarantine the message and remove matching copies where appropriate.",
            "Reset exposed credentials if compromise is suspected and review recent sign-in activity.",
            "Document affected users, evidence, and recovery actions.",
        ],
        "High": [
            "Open a high-priority incident and notify the security operations lead.",
            "Identify all recipients and determine whether credentials, sessions, or devices may be compromised.",
            "Coordinate removal of the campaign email and block confirmed malicious indicators.",
            "Revoke suspicious sessions, reset affected credentials, and enforce MFA where applicable.",
            "Review sign-in logs and endpoint alerts for follow-on activity.",
            "Escalate confirmed account compromise to the incident response team.",
        ],
        "Critical": [
            "Activate the critical-incident process and notify security leadership immediately.",
            "Preserve email, identity-provider, endpoint, and network evidence before making changes where feasible.",
            "Coordinate urgent removal of the campaign and blocking of confirmed malicious indicators.",
            "Contain compromised accounts by revoking sessions and restricting access through approved procedures.",
            "Investigate lateral movement, mailbox rules, data access, and financial fraud indicators.",
            "Coordinate legal, privacy, finance, and executive notifications according to policy.",
            "Document decisions, evidence handling, recovery approval, and post-incident actions.",
        ],
    },
    "Ransomware": {
        "Low": [
            "Record the alert, affected device, user, and observed symptoms.",
            "Check for suspicious file changes, ransom notes, or endpoint security detections.",
            "Preserve relevant alerts and logs for investigation.",
            "Escalate if encryption or additional affected devices are discovered.",
        ],
        "Medium": [
            "Notify the security team and identify potentially affected endpoints and shared folders.",
            "Isolate the suspected endpoint using approved endpoint or network controls if compromise is credible.",
            "Preserve endpoint alerts, timestamps, and available system logs.",
            "Check for suspicious processes, persistence, and access to shared storage.",
            "Verify backup availability without connecting backups to potentially compromised systems.",
        ],
        "High": [
            "Declare a high-priority incident and activate the ransomware response team.",
            "Isolate affected endpoints and restrict compromised accounts through approved procedures.",
            "Identify the encryption scope, initial access method, and possible lateral movement.",
            "Protect backup infrastructure and suspend risky backup connections where authorized.",
            "Preserve forensic evidence and determine whether sensitive data may have been accessed or exfiltrated.",
            "Prepare recovery from verified clean backups after containment and eradication.",
        ],
        "Critical": [
            "Activate the major-incident response process and notify executive and security leadership.",
            "Coordinate containment across affected endpoints, servers, identity systems, and network segments.",
            "Protect backup systems and critical finance or business services from further compromise.",
            "Preserve forensic images, security logs, ransom notes, and relevant network evidence where feasible.",
            "Assess data exfiltration, operational disruption, safety implications, and regulatory obligations.",
            "Coordinate recovery priorities with business continuity, IT, legal, and finance teams.",
            "Restore only from verified clean sources after eradication and obtain authorized recovery approval.",
        ],
    },
    "Unauthorized Access": {
        "Low": [
            "Record the account, system, timestamp, and suspicious access event.",
            "Compare the event with expected user activity and approved access permissions.",
            "Review relevant authentication logs for repeated failures or unusual locations.",
            "Escalate if the access cannot be explained or additional systems are involved.",
        ],
        "Medium": [
            "Verify the account owner and determine whether the access was authorized.",
            "Review sign-in history, privilege changes, and activity during the suspicious session.",
            "Disable or restrict the account temporarily if compromise is supported by evidence.",
            "Reset credentials and revoke sessions when account compromise is suspected.",
            "Record affected resources and any unauthorized changes.",
        ],
        "High": [
            "Notify the security operations lead and preserve identity and system logs.",
            "Contain the suspected account and revoke active sessions using approved procedures.",
            "Review privileged actions, newly created accounts, and changes to access permissions.",
            "Investigate access to sensitive corporate or financial systems.",
            "Check for persistence, lateral movement, and possible data extraction.",
            "Restore permissions only after validation and approval by the system owner.",
        ],
        "Critical": [
            "Activate the critical-incident process and notify security leadership.",
            "Coordinate containment of compromised privileged accounts and affected systems.",
            "Preserve identity, endpoint, cloud, database, and network evidence relevant to the intrusion.",
            "Investigate privilege escalation, persistence, lateral movement, and access to critical financial records.",
            "Review unauthorized transactions, data changes, and potential regulatory impact.",
            "Re-establish trusted access, rotate affected secrets, and validate security controls before recovery.",
            "Record containment decisions and obtain authorization before restoring critical access.",
        ],
    },
    "Data Breach": {
        "Low": [
            "Identify the data involved and the location where it may have been exposed.",
            "Preserve relevant access logs, sharing settings, and available evidence.",
            "Restrict unintended access to the affected file or resource where authorized.",
            "Document the known exposure and refer uncertain cases to the privacy or security team.",
        ],
        "Medium": [
            "Identify the data categories, affected records, access permissions, and exposure period.",
            "Preserve audit logs and evidence of access, sharing, downloads, or transfers.",
            "Revoke unauthorized sharing links and correct access permissions.",
            "Determine whether data was viewed, downloaded, modified, or transferred.",
            "Notify the privacy or compliance team for an impact assessment.",
        ],
        "High": [
            "Notify the incident lead, privacy team, and relevant data owner immediately.",
            "Contain the exposure by restricting access and securing affected accounts or systems.",
            "Establish the likely scope, affected individuals, sensitive data categories, and exposure timeline.",
            "Preserve access, database, cloud, and transfer logs for investigation.",
            "Assess possible financial fraud, identity misuse, contractual duties, and reporting deadlines.",
            "Coordinate any required notifications through authorized legal and compliance personnel.",
        ],
        "Critical": [
            "Activate the major-incident process and notify executive, privacy, legal, and security leadership.",
            "Contain ongoing disclosure without destroying evidence needed for investigation.",
            "Determine the scope of exposed financial, personal, confidential, and regulated information.",
            "Preserve forensic evidence and establish a reliable incident timeline.",
            "Assess continuing access, data exfiltration, fraud, operational impact, and third-party involvement.",
            "Have legal and compliance personnel determine applicable reporting and notification obligations.",
            "Coordinate stakeholder communications and remediation under the approved incident plan.",
        ],
    },
    "Malware": {
        "Low": [
            "Record the detection name, affected endpoint, user, and alert timestamp.",
            "Review the endpoint security alert and identify the suspected file or process.",
            "Run approved security checks and preserve relevant detection logs.",
            "Escalate if execution, persistence, or additional affected devices are suspected.",
        ],
        "Medium": [
            "Identify the affected endpoint and determine whether the suspicious file executed.",
            "Quarantine the file using approved endpoint security controls.",
            "Review process activity, persistence locations, and recent downloads.",
            "Isolate the endpoint if active compromise is suspected.",
            "Check for related detections on other devices and preserve evidence.",
        ],
        "High": [
            "Notify the security operations lead and coordinate endpoint containment.",
            "Isolate affected endpoints and block confirmed malicious indicators through approved controls.",
            "Investigate persistence, credential theft, command-and-control traffic, and lateral movement.",
            "Review endpoint, DNS, proxy, and authentication logs for related activity.",
            "Reimage or clean affected systems using approved procedures after evidence collection.",
            "Validate endpoint security coverage before returning devices to service.",
        ],
        "Critical": [
            "Activate the major-incident process if malware affects critical services or multiple systems.",
            "Coordinate containment across affected endpoints, servers, and network segments.",
            "Protect identity systems, backups, and critical finance or corporate workloads.",
            "Preserve forensic evidence and investigate command-and-control and data-exfiltration activity.",
            "Determine the initial infection path and identify other potentially affected systems.",
            "Eradicate malware and persistence, then restore systems from trusted sources if needed.",
            "Validate monitoring and obtain service-owner approval before restoring operations.",
        ],
    },
    "Suspicious Transaction": {
        "Low": [
            "Record the transaction reference, amount, timestamp, and relevant account details securely.",
            "Compare the transaction with approved business procedures and expected activity.",
            "Refer the case to the authorized finance or fraud-review contact.",
            "Document the review result without assuming fraud has occurred.",
        ],
        "Medium": [
            "Verify the transaction against supporting documents and approval records.",
            "Review the initiating account, payment destination, and recent account changes.",
            "Ask the authorized finance team to review or hold the transaction where policy permits.",
            "Check for similar transactions or unusual beneficiary changes.",
            "Preserve relevant application, authentication, and payment audit logs.",
        ],
        "High": [
            "Notify finance operations, security, and the designated fraud-response lead.",
            "Request an authorized hold, recall, or additional approval before settlement where possible.",
            "Review account access, beneficiary changes, payment approvals, and authentication events.",
            "Identify related transactions and assess possible business email compromise or account takeover.",
            "Preserve payment records and coordinate with the relevant bank or payment provider through approved channels.",
            "Document financial exposure and escalation decisions.",
        ],
        "Critical": [
            "Activate the critical financial-fraud response process and notify authorized leadership immediately.",
            "Coordinate urgent payment holds, recalls, or account restrictions with finance and banking partners where possible.",
            "Secure potentially compromised payment and approval accounts using approved procedures.",
            "Investigate linked transactions, beneficiary manipulation, privileged access, and possible data compromise.",
            "Preserve transaction records, approval trails, identity logs, and communications.",
            "Engage legal, compliance, and fraud teams to assess reporting and recovery obligations.",
            "Track confirmed and potential losses separately and document all authorized decisions.",
        ],
    },
    "Denial of Service": {
        "Low": [
            "Record the service, start time, observed errors, and affected users.",
            "Check availability monitoring, server health, and recent configuration changes.",
            "Review traffic levels and logs for unusual request patterns.",
            "Escalate if service degradation continues or the impact increases.",
        ],
        "Medium": [
            "Notify the IT operations team and assess service availability and user impact.",
            "Review traffic patterns, resource utilization, and relevant network or application logs.",
            "Apply approved rate limits or filtering rules if supported by the evidence.",
            "Check upstream network, hosting, and service-provider status.",
            "Monitor recovery and record the effectiveness of mitigation.",
        ],
        "High": [
            "Activate the service incident process and notify the security and infrastructure leads.",
            "Coordinate mitigation with network, hosting, CDN, or DDoS protection providers.",
            "Apply approved filtering, rate limiting, or traffic scrubbing to protect critical services.",
            "Prioritize essential corporate and financial services and assess dependencies.",
            "Preserve traffic and application logs for later analysis.",
            "Monitor service health and communicate impact to affected stakeholders.",
        ],
        "Critical": [
            "Activate the major-incident process and notify executive and business continuity leads.",
            "Coordinate urgent mitigation with network operators and relevant protection providers.",
            "Prioritize recovery of critical finance, authentication, and customer-facing services.",
            "Apply authorized traffic controls while monitoring for collateral service impact.",
            "Assess whether the event masks intrusion attempts or coincides with other attacks.",
            "Maintain an incident timeline, stakeholder updates, and recovery checkpoints.",
            "Validate service stability and document lessons and capacity improvements.",
        ],
    },
    "Other": {
        "Low": [
            "Record the observed security event, affected asset, timestamp, and reporting source.",
            "Gather relevant logs and verify the reported behavior.",
            "Assign an owner to investigate and document findings.",
            "Escalate if evidence suggests compromise or broader impact.",
        ],
        "Medium": [
            "Assign an incident owner and identify affected users, systems, and business processes.",
            "Preserve relevant logs, alerts, and supporting evidence.",
            "Assess the likely scope and apply proportionate, authorized containment.",
            "Check for related alerts or similar events elsewhere in the environment.",
            "Record findings and define follow-up actions.",
        ],
        "High": [
            "Notify the incident response lead and prioritize investigation.",
            "Preserve relevant endpoint, identity, application, and network evidence.",
            "Contain confirmed affected accounts or systems through approved procedures.",
            "Assess lateral movement, sensitive data access, and operational impact.",
            "Coordinate with the relevant IT, finance, privacy, or compliance owners.",
            "Document recovery criteria and obtain appropriate approval.",
        ],
        "Critical": [
            "Activate the critical-incident process and notify security leadership.",
            "Establish incident command, assign response owners, and maintain a decision log.",
            "Coordinate urgent containment of affected systems and accounts.",
            "Preserve evidence and assess impact on critical corporate and financial operations.",
            "Engage business continuity, legal, privacy, finance, and external responders as required.",
            "Define recovery priorities, validation requirements, and authorized approval steps.",
            "Complete a post-incident review and track corrective actions to closure.",
        ],
    },
}


def get_checklist(incident_type, severity):
    """Return the tailored response checklist for an incident."""
    incident_plans = PLAYBOOKS.get(incident_type, PLAYBOOKS["Other"])
    return list(incident_plans.get(severity, incident_plans["Medium"]))


def get_recommendations(incident_type, severity):
    """Compatibility helper for existing app code."""
    return get_checklist(incident_type, severity)
