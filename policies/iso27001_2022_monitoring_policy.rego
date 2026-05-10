# ISO/IEC 27001:2022 Control 5.18 - Monitoring, Measurement, Analysis and Evaluation (NEW emphasis in 2022)
# ISO/IEC 27001:2022 Control 5.23 - Cloud Service Security Monitoring (NEW in 2022)
# ISO/IEC 27001:2022 Control 5.1 - Information Security Policies (Measurement focus)
# Policy: Enhanced monitoring and metrics as required by ISO 27001:2022

package iso27001_2022.monitoring

import data.azure.resources
import data.azure.metrics
import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ISO 27001:2022 A.5.18 - Monitoring (NEW Control emphasis in 2022)
# All systems must have continuous monitoring enabled
deny[msg] {
    resource := resources.all_resources[_]
    resource.monitoring_enabled == false
    resource.criticality in ["Critical", "High"]
    msg := sprintf("ISO 27001:2022 A.5.18: Critical resource %s (%s) missing continuous monitoring", [resource.name, resource.type])
}

# ISO 27001:2022 A.5.18.1 - Monitoring for Information Processing Facilities
# Mandatory log collection and retention
deny[msg] {
    resource := resources.all_resources[_]
    resource.audit_logging.enabled == false
    msg := sprintf("ISO 27001:2022 A.5.18.1: Resource %s missing audit logging required by 2022 monitoring controls", [resource.name])
}

# ISO 27001:2022 A.5.18.1 - Enhanced Log Retention (60+ days minimum vs 90 in 2013)
deny[msg] {
    resource := resources.all_resources[_]
    resource.audit_logging.retention_days < 60
    resource.audit_logging.enabled == true
    msg := sprintf("ISO 27001:2022 A.5.18.1: Resource %s logs retained %d days, minimum 60 required per 2022", [resource.name, resource.audit_logging.retention_days])
}

# ISO 27001:2022 A.5.23.1 - Cloud Service Monitoring (NEW in 2022)
# Cloud resources require continuous security monitoring
deny[msg] {
    cloud_resource := resources.cloud_resources[_]
    cloud_resource.security_monitoring_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.23.1: Cloud resource %s lacks continuous security monitoring (NEW 2022 requirement)", [cloud_resource.name])
}

# ISO 27001:2022 A.5.23.2 - Cloud Incident Monitoring (NEW in 2022)
# Cloud resources must alert on security incidents
deny[msg] {
    cloud_resource := resources.cloud_resources[_]
    cloud_resource.incident_alerting_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.23.2: Cloud resource %s lacks incident alerting (NEW 2022 requirement)", [cloud_resource.name])
}

# ISO 27001:2022 A.5.18 - Measurement Requirements (NEW emphasis)
# Organization must measure control effectiveness
deny[msg] {
    control := resources.controls[_]
    metrics := control.measurement_metrics
    not metrics
    msg := sprintf("ISO 27001:2022 A.5.18: Control %s lacks measurement metrics - violates 2022 measurement requirement", [control.control_id])
}

# ISO 27001:2022 A.5.18 - Performance Metrics (NEW in 2022)
# MTTR (Mean Time to Respond) and MTPD (Mean Time to Detect) tracking
deny[msg] {
    metric := metrics.incident_metrics[_]
    not metric.mttr
    msg := "ISO 27001:2022 A.5.18: Incident response MTTR not tracked - violates 2022 metrics requirement"
}

deny[msg] {
    metric := metrics.incident_metrics[_]
    metric.mttr > 4
    msg := "ISO 27001:2022 A.5.18: Incident response MTTR exceeds 4 hours - violates 2022 metrics requirement"
}

deny[msg] {
    metric := metrics.incident_metrics[_]
    not metric.mtpd
    msg := "ISO 27001:2022 A.5.18: Incident detection MTPD not tracked - violates 2022 metrics requirement"
}

deny[msg] {
    metric := metrics.incident_metrics[_]
    metric.mtpd > 1
    msg := "ISO 27001:2022 A.5.18: Incident detection MTPD exceeds 1 hour - violates 2022 metrics requirement"
}

# ISO 27001:2022 A.5.23.1 - Cloud Transparency/Reporting
# Cloud providers must provide monitoring data
deny[msg] {
    cloud_service := resources.cloud_services[_]
    cloud_service.provider_monitoring_reports == false
    msg := sprintf("ISO 27001:2022 A.5.23.1: Cloud service %s lacks provider monitoring reports (2022 transparency requirement)", [cloud_service.name])
}

# ISO 27001:2022 M365 Defender Monitoring (Cloud security emphasis)
deny[msg] {
    tenant := resources.m365_tenants[_]
    tenant.defender_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.23: M365 tenant %s missing Defender (2022 cloud security requirement)", [tenant.displayName])
}

# ISO 27001:2022 A.5.18 - Audit Log Analysis (NEW emphasis)
deny[msg] {
    audit_log := resources.audit_logs[_]
    audit_log.automated_analysis_enabled == false
    audit_log.suspicious_activity_detection == false
    msg := sprintf("ISO 27001:2022 A.5.18: Audit logs for %s lack automated analysis (2022 monitoring requirement)", [audit_log.resource_name])
}

# ISO 27001:2022 A.5.12.4.1 - Logging of Access Rights Modifications (Enhanced tracking)
deny[msg] {
    access_log := resources.access_logs[_]
    access_log.access_rights_changes_logged == false
    msg := sprintf("ISO 27001:2022 A.5.12.4.1: Access rights changes not logged for %s", [access_log.resource_name])
}

# ISO 27001:2022 A.5.23 - Real-time Alerting for Cloud (2022 requirement)
deny[msg] {
    cloud_resource := resources.cloud_resources[_]
    cloud_resource.contains_sensitive_data == true
    cloud_resource.realtime_alerting_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.23: Sensitive cloud resource %s lacks real-time alerting (2022 requirement)", [cloud_resource.name])
}

# Audit: SIEM Integration (best practice for 2022 monitoring)
audit[msg] {
    resource := resources.all_resources[_]
    resource.siem_integrated == false
    resource.criticality in ["Critical", "High"]
    msg := sprintf("ISO 27001:2022 A.5.18: Critical resource %s should integrate with SIEM per 2022 best practices", [resource.name])
}

# Audit: KPI Tracking (2022 measurement emphasis)
audit[msg] {
    organization := resources.organization[_]
    organization.isms_metrics_tracked == false
    msg := "ISO 27001:2022 A.5.18: Organization should track ISMS KPIs per 2022 measurement requirements"
}

# Test cases
test_compliant_monitoring {
    resource := {
        "name": "prod-db",
        "type": "Database",
        "criticality": "Critical",
        "monitoring_enabled": true,
        "audit_logging": {
            "enabled": true,
            "retention_days": 365,
            "automated_analysis_enabled": true
        },
        "security_monitoring_enabled": true,
        "incident_alerting_enabled": true
    }
    count(deny) == 0
}

test_no_monitoring {
    resource := {
        "name": "prod-db",
        "type": "Database",
        "criticality": "Critical",
        "monitoring_enabled": false
    }
    count(deny) > 0
}

test_insufficient_retention {
    resource := {
        "name": "prod-app",
        "audit_logging": {
            "enabled": true,
            "retention_days": 30
        }
    }
    count(deny) > 0
}

test_cloud_no_monitoring {
    cloud_resource := {
        "name": "azure-app",
        "security_monitoring_enabled": false,
        "incident_alerting_enabled": false
    }
    count(deny) > 0
}
