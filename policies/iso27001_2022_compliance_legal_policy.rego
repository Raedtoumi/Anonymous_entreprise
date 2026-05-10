# ISO/IEC 27001:2022 Control 5.14 - Compliance
# Policy: Legal, regulatory, and contractual requirements

package iso27001_2022.compliance

import data.compliance
import future.keywords.contains

# ISO 27001:2022 A.5.14.1 - Information Security Policies & Objectives
deny[msg] {
    organization := compliance.organization[_]
    organization.information_security_policy == false
    msg := "ISO 27001:2022 A.5.14.1: No information security policy - violates compliance requirement"
}

deny[msg] {
    organization := compliance.organization[_]
    organization.information_security_objectives == false
    msg := "ISO 27001:2022 A.5.14.1: No information security objectives - violates compliance requirement"
}

# ISO 27001:2022 A.5.14.1 - Policy Review & Communication
deny[msg] {
    policy := compliance.policies[_]
    not policy.last_review
    msg := sprintf("ISO 27001:2022 A.5.14.1: Policy %s never reviewed - violates periodic review", [policy.policy_id])
}

deny[msg] {
    policy := compliance.policies[_]
    policy.last_review != ""
    days_since_review := (time.now_ns() / 1000000000 - policy.last_review) / 86400
    days_since_review > 365
    msg := sprintf("ISO 27001:2022 A.5.14.1: Policy %s not reviewed for %d days (require annual)", [policy.policy_id, days_since_review])
}

deny[msg] {
    policy := compliance.policies[_]
    policy.communicated_to_employees == false
    msg := sprintf("ISO 27001:2022 A.5.14.1: Policy %s not communicated to employees", [policy.policy_id])
}

# ISO 27001:2022 A.5.14.2 - Information Security Compliance Monitoring
deny[msg] {
    organization := compliance.organization[_]
    organization.compliance_monitoring_program == false
    msg := "ISO 27001:2022 A.5.14.2: No compliance monitoring program - violates compliance assessment"
}

# ISO 27001:2022 A.5.14.2 - Regulatory Compliance Assessment
deny[msg] {
    regulation := compliance.regulations[_]
    regulation.compliance_assessed == false
    msg := sprintf("ISO 27001:2022 A.5.14.2: Regulation/law %s not assessed - violates compliance requirement", [regulation.regulation_name])
}

deny[msg] {
    regulation := compliance.regulations[_]
    regulation.compliance_status == "Non-Compliant"
    regulation.remediation_plan == false
    msg := sprintf("ISO 27001:2022 A.5.14.2: Non-compliance with %s lacks remediation plan", [regulation.regulation_name])
}

# ISO 27001:2022 A.5.14.2 - Audit & Assessment
deny[msg] {
    organization := compliance.organization[_]
    organization.information_security_audit == false
    msg := "ISO 27001:2022 A.5.14.2: No independent security audit conducted - violates assessment requirement"
}

deny[msg] {
    audit := compliance.audits[_]
    audit.audit_completed == true
    audit.findings_addressed == false
    audit.days_since_completion > 30
    msg := sprintf("ISO 27001:2022 A.5.14.2: Audit %s findings not addressed 30+ days post-audit", [audit.audit_id])
}

# ISO 27001:2022 A.5.14.2 - Data Protection Compliance (GDPR, etc)
deny[msg] {
    organization := compliance.organization[_]
    organization.data_protection_dpia == false
    organization.processes_personal_data == true
    msg := "ISO 27001:2022 A.5.14.2: DPIA not completed despite processing personal data"
}

# ISO 27001:2022 A.5.14.2 - Data Subject Rights
deny[msg] {
    organization := compliance.organization[_]
    organization.data_subject_rights_procedure == false
    msg := "ISO 27001:2022 A.5.14.2: No data subject rights procedure - violates data protection compliance"
}

# ISO 27001:2022 A.5.14.2 - Data Breach Notification
deny[msg] {
    organization := compliance.organization[_]
    organization.breach_notification_procedure == false
    msg := "ISO 27001:2022 A.5.14.2: No breach notification procedure - violates compliance requirement"
}

# ISO 27001:2022 A.5.14.2 - Records & Documentation
deny[msg] {
    organization := compliance.organization[_]
    organization.isms_documentation_maintained == false
    msg := "ISO 27001:2022 A.5.14.2: ISMS documentation not maintained - violates evidence requirement"
}

# ISO 27001:2022 A.5.14.2 - Retention Requirements
deny[msg] {
    record := compliance.records[_]
    not record.retention_period
    msg := sprintf("ISO 27001:2022 A.5.14.2: Record %s has no retention period defined", [record.record_id])
}

# ISO 27001:2022 A.5.14.2 - Third-Party/Supplier Compliance
deny[msg] {
    supplier := compliance.suppliers[_]
    supplier.compliance_assessed == false
    supplier.processes_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.14.2: Supplier %s processing sensitive data not assessed for compliance", [supplier.name])
}

# ISO 27001:2022 A.5.14.2 - Contractual Compliance
deny[msg] {
    contract := compliance.contracts[_]
    contract.security_requirements_included == false
    contract.handles_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.14.2: Contract %s lacks security requirements despite sensitive data", [contract.contract_id])
}

# ISO 27001:2022 A.5.14.2 - Control Effectiveness Measurement
deny[msg] {
    control := compliance.controls[_]
    control.effectiveness_measured == false
    msg := sprintf("ISO 27001:2022 A.5.14.2: Control %s effectiveness not measured - violates measurement requirement", [control.control_id])
}

# ISO 27001:2022 A.5.14.2 - Incident Reporting to Authorities
deny[msg] {
    incident := compliance.security_incidents[_]
    incident.requires_authority_notification == true
    incident.notification_sent == false
    incident.hours_since_detection > 72
    msg := sprintf("ISO 27001:2022 A.5.14.2: Notifiable incident %s not reported to authorities within 72 hours", [incident.incident_id])
}

# ISO 27001:2022 A.5.14.2 - Management Review
deny[msg] {
    organization := compliance.organization[_]
    organization.management_review_completed == false
    msg := "ISO 27001:2022 A.5.14.2: Management review of ISMS not completed - violates compliance review"
}

deny[msg] {
    review := compliance.management_reviews[_]
    review.last_completed != ""
    days_since_review := (time.now_ns() / 1000000000 - review.last_completed) / 86400
    days_since_review > 365
    msg := sprintf("ISO 27001:2022 A.5.14.2: Management review not completed for %d days (require annual)", [days_since_review])
}

# Audit: Policy effectiveness evaluation
audit[msg] {
    policy := compliance.policies[_]
    policy.effectiveness_evaluated == false
    msg := sprintf("ISO 27001:2022 A.5.14.2: Policy %s effectiveness not evaluated - recommend evaluation", [policy.policy_id])
}

# Audit: Regulatory landscape monitoring
audit[msg] {
    organization := compliance.organization[_]
    organization.regulatory_monitoring_process == false
    msg := "ISO 27001:2022 A.5.14.2: Regulatory landscape monitoring not established - recommend process"
}

# Test cases
test_compliant_organization {
    org := {
        "information_security_policy": true,
        "information_security_objectives": true,
        "compliance_monitoring_program": true,
        "information_security_audit": true,
        "data_protection_dpia": true,
        "breach_notification_procedure": true,
        "isms_documentation_maintained": true,
        "management_review_completed": true
    }
    count(deny) == 0
}

test_no_security_policy {
    count(deny) > 0 with data.compliance.organization as [{
        "information_security_policy": false
    }]
}

test_overdue_policy_review {
    count(deny) > 0 with data.compliance.policies as [{
        "policy_id": "POL-001",
        "last_review": 1704000000
    }]
}

test_unaddressed_audit_findings {
    count(deny) > 0 with data.compliance.audits as [{
        "audit_id": "AUD-001",
        "audit_completed": true,
        "findings_addressed": false,
        "days_since_completion": 40
    }]
}
