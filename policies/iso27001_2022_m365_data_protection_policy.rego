# ISO/IEC 27001:2022 Control 5.19 - Information Security Event Management and Improvement (Enhanced)
# ISO/IEC 27001:2022 Control 5.23 - Information Security for Cloud Services (NEW in 2022)
# ISO/IEC 27001:2022 Control 5.9 - Supplier Relationships (Enhanced in 2022)
# Policy: M365 data protection with 2022 cloud and supply chain security

package iso27001_2022.m365_data_protection

import data.m365.resources
import future.keywords.if
import future.keywords.contains

# ISO 27001:2022 A.5.23 - Cloud Services Security (NEW major section)
# All cloud data must be classified
deny[msg] {
    file := resources.m365_files[_]
    file.classification == "" or file.classification == null
    msg := sprintf("ISO 27001:2022 A.5.23: M365 file %s unclassified - violates cloud data classification (NEW 2022)", [file.path])
}

# ISO 27001:2022 A.5.23 - Cloud Data Residency (NEW requirement)
deny[msg] {
    resource := resources.m365_resources[_]
    resource.data_residency == "Multi-region" or resource.data_residency == "Unspecified"
    resource.classification in ["Confidential", "Restricted"]
    msg := sprintf("ISO 27001:2022 A.5.23: M365 resource %s contains sensitive data with undefined residency (2022 requirement)", [resource.name])
}

# ISO 27001:2022 A.5.23.1 - Cloud Provider Security Assessment (NEW in 2022)
deny[msg] {
    cloud_provider := resources.cloud_providers[_]
    cloud_provider.security_assessment_status == "Not Completed"
    msg := sprintf("ISO 27001:2022 A.5.23.1: Cloud provider %s missing required security assessment (NEW 2022)", [cloud_provider.name])
}

# ISO 27001:2022 A.5.9.1 - Supplier Third-party Requirements (Enhanced in 2022)
# M365 data sharing agreements must include security requirements
deny[msg] {
    share := resources.m365_external_shares[_]
    share.contains_sensitive_data == true
    share.data_processing_agreement == false
    msg := sprintf("ISO 27001:2022 A.5.9.1: External share %s contains sensitive data without DPA (2022 requirement)", [share.shared_with])
}

# ISO 27001:2022 A.5.23 - Cloud Service Continuity
deny[msg] {
    cloud_service := resources.cloud_services[_]
    cloud_service.availability_sla == "" or cloud_service.availability_sla == null
    cloud_service.criticality in ["Critical", "High"]
    msg := sprintf("ISO 27001:2022 A.5.23: Critical cloud service %s lacks defined SLA (2022 requirement)", [cloud_service.name])
}

# ISO 27001:2022 A.5.23.2 - Cloud Incident Response (NEW in 2022)
deny[msg] {
    cloud_resource := resources.m365_resources[_]
    cloud_resource.incident_response_procedure == false
    cloud_resource.contains_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.23.2: M365 resource %s lacks incident response procedure (NEW 2022)", [cloud_resource.name])
}

# ISO 27001:2022 A.5.19.1 - Sensitive Data Handling (DLP requirement)
deny[msg] {
    file := resources.m365_files[_]
    file.classification in ["Confidential", "Restricted"]
    file.dlp_policy_applied == false
    msg := sprintf("ISO 27001:2022 A.5.19.1: Sensitive file %s lacks DLP protection (2022 data protection)", [file.path])
}

# ISO 27001:2022 A.5.23 - Information Transfer Security (Enhanced for cloud)
deny[msg] {
    transfer := resources.m365_data_transfers[_]
    transfer.encryption_enabled == false
    transfer.data_classification in ["Confidential", "Restricted"]
    msg := sprintf("ISO 27001:2022 A.5.23: Data transfer %s lacks encryption for sensitive data", [transfer.transfer_id])
}

# ISO 27001:2022 A.5.23 - Cloud User Access Monitoring (NEW emphasis)
deny[msg] {
    tenant := resources.m365_tenants[_]
    tenant.user_access_logging_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.23: M365 tenant %s lacks user access logging (2022 cloud monitoring)", [tenant.displayName])
}

# ISO 27001:2022 A.5.23 - Data Deletion/Return on Service Termination
deny[msg] {
    cloud_service := resources.m365_subscriptions[_]
    cloud_service.data_deletion_policy == false
    msg := sprintf("ISO 27001:2022 A.5.23: M365 subscription %s lacks data deletion policy on termination (2022 requirement)", [cloud_service.name])
}

# ISO 27001:2022 A.5.19.2 - Handling of Information Assets (Cloud-specific)
deny[msg] {
    resource := resources.m365_resources[_]
    resource.owner_assigned == false
    msg := sprintf("ISO 27001:2022 A.5.19.2: M365 resource %s lacks assigned owner (2022 asset management)", [resource.name])
}

# ISO 27001:2022 A.5.9.2 - Supplier Incident Coordination (NEW in 2022)
deny[msg] {
    vendor := resources.m365_vendors[_]
    vendor.incident_notification_sla == "" or vendor.incident_notification_sla == null
    msg := sprintf("ISO 27001:2022 A.5.9.2: M365 vendor %s lacks incident notification SLA (NEW 2022)", [vendor.name])
}

# ISO 27001:2022 A.5.23 - Container/Microservices Security (if using cloud-native)
deny[msg] {
    container := resources.containers[_]
    container.image_scanning_enabled == false
    container.contains_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.23: Container %s with sensitive data lacks image scanning (2022 cloud-native security)", [container.name])
}

# ISO 27001:2022 Sensitive Data Classification and Retention (Enhanced)
deny[msg] {
    file := resources.m365_files[_]
    file.classification in ["Confidential", "Restricted"]
    file.retention_label == "" or file.retention_label == null
    msg := sprintf("ISO 27001:2022 A.5.19: Classified file %s lacks retention label", [file.path])
}

# Audit: Cloud Risk Assessment (2022 best practice)
audit[msg] {
    cloud_service := resources.cloud_services[_]
    cloud_service.risk_assessment_completed == false
    msg := sprintf("ISO 27001:2022 A.5.23: Cloud service %s should have risk assessment per 2022 best practices", [cloud_service.name])
}

# Audit: Supply Chain Security Review (Enhanced in 2022)
audit[msg] {
    vendor := resources.vendors[_]
    vendor.security_review_last_completed > 365
    vendor.provides_critical_services == true
    msg := sprintf("ISO 27001:2022 A.5.9: Vendor %s security review is %d days old (recommend annual review)", [vendor.name, vendor.security_review_last_completed])
}

# Test cases
test_compliant_sensitive_file {
    file := {
        "path": "/teams/finance/data.xlsx",
        "classification": "Confidential",
        "retention_label": "Confidential-7Y",
        "dlp_policy_applied": true,
        "owner_assigned": true,
        "encryption_enabled": true,
        "data_residency": "Europe"
    }
    count(deny) == 0
}

test_unclassified_cloud_file {
    file := {
        "path": "/teams/data.xlsx",
        "classification": ""
    }
    count(deny) > 0
}

test_sensitive_no_dpa {
    share := {
        "shared_with": "external-vendor@company.com",
        "contains_sensitive_data": true,
        "data_processing_agreement": false
    }
    count(deny) > 0
}

test_cloud_provider_no_assessment {
    provider := {
        "name": "Microsoft",
        "security_assessment_status": "Not Completed"
    }
    count(deny) > 0
}
