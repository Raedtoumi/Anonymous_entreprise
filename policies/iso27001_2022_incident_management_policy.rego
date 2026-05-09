# ISO/IEC 27001:2022 Control 5.12 - Information Security Incident Management
# ISO/IEC 27001:2022 Control 5.13 - Business Continuity Management
# Policy: Incident response, business continuity, and disaster recovery

package iso27001_2022.incident_management

import data.incidents
import data.business_continuity
import future.keywords.contains

# ISO 27001:2022 A.5.12.1 - Incident Response Plan (mandatory)
deny[msg] {
    organization := incidents.organization[_]
    organization.incident_response_plan == false
    msg := sprintf("ISO 27001:2022 A.5.12.1: No incident response plan defined - violates incident management")
}

# ISO 27001:2022 A.5.12.1 - Incident Response Team (mandatory)
deny[msg] {
    organization := incidents.organization[_]
    count(organization.incident_response_team) < 3
    msg := sprintf("ISO 27001:2022 A.5.12.1: Incident response team incomplete (need min 3 roles)")
}

# ISO 27001:2022 A.5.12.2 - Incident Reporting & Communication
deny[msg] {
    incident := incidents.security_incidents[_]
    incident.reported == false
    incident.severity in ["Critical", "High"]
    incident.days_since_detection > 1
    msg := sprintf("ISO 27001:2022 A.5.12.2: Critical incident %s not reported after %d days", [incident.incident_id, incident.days_since_detection])
}

# ISO 27001:2022 A.5.12.2 - Incident Classification (mandatory)
deny[msg] {
    incident := incidents.security_incidents[_]
    classification := incident.classification
    not classification
    msg := sprintf("ISO 27001:2022 A.5.12.2: Incident %s not classified - violates incident documentation", [incident.incident_id])
}

# ISO 27001:2022 A.5.12.3 - Incident Assessment & Investigation
deny[msg] {
    incident := incidents.security_incidents[_]
    incident.severity in ["Critical", "High"]
    incident.investigation_started == false
    incident.hours_since_detection > 4
    msg := sprintf("ISO 27001:2022 A.5.12.3: Critical incident %s investigation not started within 4 hours", [incident.incident_id])
}

# ISO 27001:2022 A.5.12.4 - Incident Containment & Recovery
deny[msg] {
    incident := incidents.security_incidents[_]
    incident.severity in ["Critical", "High"]
    incident.containment_actions == false
    msg := sprintf("ISO 27001:2022 A.5.12.4: Critical incident %s lacks containment actions", [incident.incident_id])
}

# ISO 27001:2022 A.5.12.5 - Incident Learning & Improvement
deny[msg] {
    incident := incidents.closed_incidents[_]
    incident.severity in ["Critical", "High"]
    incident.root_cause_analysis == false
    incident.days_since_close > 30
    msg := sprintf("ISO 27001:2022 A.5.12.5: Closed incident %s missing RCA 30 days post-close", [incident.incident_id])
}

# ISO 27001:2022 A.5.12 - Forensics Capability
deny[msg] {
    organization := incidents.organization[_]
    organization.forensics_capability == false
    msg := sprintf("ISO 27001:2022 A.5.12: No digital forensics capability - violates incident investigation requirement")
}

# ISO 27001:2022 A.5.13.1 - Business Continuity Policy (mandatory)
deny[msg] {
    organization := business_continuity.organization[_]
    organization.bc_policy_published == false
    msg := sprintf("ISO 27001:2022 A.5.13.1: No business continuity policy - violates BC management")
}

# ISO 27001:2022 A.5.13.2 - Business Continuity Planning
deny[msg] {
    bc_plan := business_continuity.bc_plans[_]
    (bc_plan.rto == "") or (bc_plan.rto == null) or (bc_plan.rto > 4)
    bc_plan.criticality in ["Critical", "High"]
    msg := sprintf("ISO 27001:2022 A.5.13.2: Critical service %s RTO not defined or >4 hours", [bc_plan.service_name])
}

deny[msg] {
    bc_plan := business_continuity.bc_plans[_]
    (bc_plan.rpo == "") or (bc_plan.rpo == null) or (bc_plan.rpo > 1)
    bc_plan.criticality in ["Critical", "High"]
    msg := sprintf("ISO 27001:2022 A.5.13.2: Critical service %s RPO not defined or >1 hour", [bc_plan.service_name])
}

# ISO 27001:2022 A.5.13.3 - Backup & Recovery (mandatory)
deny[msg] {
    resource := business_continuity.resources[_]
    resource.backup_enabled == false
    resource.criticality in ["Critical", "High"]
    msg := sprintf("ISO 27001:2022 A.5.13.3: Critical resource %s backup not enabled", [resource.resource_id])
}

# ISO 27001:2022 A.5.13.3 - Backup Testing
deny[msg] {
    backup := business_continuity.backups[_]
    test := backup.last_restore_test
    not test
    msg := sprintf("ISO 27001:2022 A.5.13.3: Backup %s never tested - violates backup validation", [backup.backup_id])
}

deny[msg] {
    backup := business_continuity.backups[_]
    backup.last_restore_test != ""
    days_since_test := (now - backup.last_restore_test) / 86400
    days_since_test > 90
    msg := sprintf("ISO 27001:2022 A.5.13.3: Backup %s last tested %d days ago (recommend quarterly)", [backup.backup_id, days_since_test])
}

# ISO 27001:2022 A.5.13.4 - Disaster Recovery Testing (mandatory)
deny[msg] {
    plan := business_continuity.dr_plans[_]
    plan.test_executed == false
    msg := sprintf("ISO 27001:2022 A.5.13.4: DR Plan %s never tested - violates DR testing requirement", [plan.plan_id])
}

deny[msg] {
    plan := business_continuity.dr_plans[_]
    plan.last_test != ""
    days_since_test := (now - plan.last_test) / 86400
    days_since_test > 365
    msg := sprintf("ISO 27001:2022 A.5.13.4: DR Plan %s last tested %d days ago - requires annual test", [plan.plan_id, days_since_test])
}

# ISO 27001:2022 A.5.13.4 - DR Test Success Rate
deny[msg] {
    plan := business_continuity.dr_plans[_]
    plan.test_success_rate < 80
    msg := sprintf("ISO 27001:2022 A.5.13.4: DR Plan %s success rate %d%% (require >80%%)", [plan.plan_id, plan.test_success_rate])
}

# Audit: Crisis communication plan
audit[msg] {
    organization := incidents.organization[_]
    organization.crisis_communication_plan == false
    msg := sprintf("ISO 27001:2022 A.5.12: Crisis communication plan recommended")
}

# Audit: Third-party incident coordination
audit[msg] {
    organization := incidents.organization[_]
    organization.third_party_incident_procedures == false
    msg := sprintf("ISO 27001:2022 A.5.12: Third-party incident coordination procedures recommended")
}

# Test cases
test_compliant_incident {
    incident := {
        "incident_id": "INC-001",
        "severity": "High",
        "reported": true,
        "classification": "Data Breach",
        "investigation_started": true,
        "hours_since_detection": 2,
        "containment_actions": true
    }
    count(deny) == 0
}

test_unreported_incident {
    incident := {
        "incident_id": "INC-001",
        "severity": "Critical",
        "reported": false,
        "days_since_detection": 2
    }
    count(deny) > 0
}

test_no_dr_testing {
    plan := {
        "plan_id": "DR-001",
        "test_executed": false
    }
    count(deny) > 0
}

test_compliant_backup {
    backup := {
        "backup_id": "BK-001",
        "last_restore_test": 1715000000,
        "criticality": "Critical",
        "backup_enabled": true
    }
    count(deny) == 0
}
