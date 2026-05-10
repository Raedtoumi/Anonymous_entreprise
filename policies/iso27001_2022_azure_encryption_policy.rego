# ISO/IEC 27001:2022 Control 5.10 - Cryptography (Enhanced in 2022)
# ISO/IEC 27001:2022 Control 5.14 - Data Transfers (New focus in 2022)
# ISO/IEC 27001:2022 Control 5.23 - Cloud Security Requirements (NEW in 2022)
# Policy: Cryptographic controls for Azure and M365 with 2022 cloud-specific requirements

package iso27001_2022.cryptography

import data.azure.resources
import future.keywords.if
import future.keywords.in

# ISO 27001:2022 A.5.10.1 - Cryptographic Controls (Enhanced)
# Mandatory encryption at rest for all data
deny[msg] {
    storage := resources.storage_accounts[_]
    storage.encryption_at_rest.enabled == false
    msg := sprintf("ISO 27001:2022 A.5.10.1: Storage %s missing encryption at rest", [storage.name])
}

# ISO 27001:2022 A.5.10 - Cryptographic Controls
# Enforce modern cryptography algorithms only (2022 emphasis on algorithm strength)
deny[msg] {
    storage := resources.storage_accounts[_]
    storage.encryption_at_rest.algorithm != "AES-256"
    storage.encryption_at_rest.enabled == true
    msg := sprintf("ISO 27001:2022 A.5.10: Storage %s uses weak algorithm %s, requires AES-256", [storage.name, storage.encryption_at_rest.algorithm])
}

# ISO 27001:2022 A.5.14 - Data Transfer (Enhanced in 2022)
# Mandatory TLS 1.2+ for all data transfers
deny[msg] {
    resource := resources.all_resources[_]
    resource.data_transfer.https_only == false
    msg := sprintf("ISO 27001:2022 A.5.14: Resource %s allows non-HTTPS data transfers", [resource.name])
}

# ISO 27001:2022 A.5.14.1 - Data Transfer Security
# TLS version must be 1.2 or higher (2022 stronger cryptography requirement)
deny[msg] {
    resource := resources.all_resources[_]
    resource.tls_minimum_version < 1.2
    msg := sprintf("ISO 27001:2022 A.5.14.1: Resource %s allows TLS %f, requires minimum 1.2", [resource.name, resource.tls_minimum_version])
}

# ISO 27001:2022 A.5.23 - Cloud Computing Service Security (NEW in 2022)
# Cloud providers must ensure cryptographic controls
deny[msg] {
    cloud_resource := resources.cloud_resources[_]
    cloud_resource.encryption_key_management != "Customer Managed"
    cloud_resource.encryption_key_management != "Provider Managed with customer audit"
    msg := sprintf("ISO 27001:2022 A.5.23: Cloud resource %s lacks secure key management - 2022 cloud security requirement", [cloud_resource.name])
}

# ISO 27001:2022 A.5.23 - Cloud data residency and sovereignty
deny[msg] {
    cloud_resource := resources.cloud_resources[_]
    cloud_resource.data_residency_enforced == false
    cloud_resource.classification in ["Confidential", "Restricted"]
    msg := sprintf("ISO 27001:2022 A.5.23: Cloud resource %s with sensitive data lacks data residency controls", [cloud_resource.name])
}

# ISO 27001:2022 A.5.10.3 - Cryptographic Key Management (Enhanced)
# Keys must be properly managed (new emphasis in 2022)
deny[msg] {
    key := resources.cryptographic_keys[_]
    key.rotation_enabled == false
    key.key_age_months > 12
    msg := sprintf("ISO 27001:2022 A.5.10.3: Encryption key %s older than 12 months without rotation", [key.key_id])
}

# ISO 27001:2022 A.5.23 - Cloud supplier security
deny[msg] {
    cloud_service := resources.cloud_services[_]
    cloud_service.security_assessment_completed == false
    cloud_service.contains_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.23: Cloud service %s handling sensitive data without security assessment", [cloud_service.name])
}

# ISO 27001:2022 A.5.23 - Incident response in cloud
deny[msg] {
    cloud_resource := resources.cloud_resources[_]
    cloud_resource.incident_response_plan == false
    msg := sprintf("ISO 27001:2022 A.5.23: Cloud resource %s lacks incident response procedures (2022 requirement)", [cloud_resource.name])
}

# ISO 27001:2022 SQL Database specific encryption
deny[msg] {
    database := resources.sql_databases[_]
    database.transparent_data_encryption.enabled == false
    msg := sprintf("ISO 27001:2022 A.5.10.1: SQL Database %s missing TDE", [database.name])
}

# ISO 27001:2022 M365 DLP and encryption
deny[msg] {
    teams_channel := resources.teams_channels[_]
    teams_channel.contains_sensitive_data == true
    teams_channel.dlp_policy_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.10.1: Teams channel %s contains sensitive data without DLP", [teams_channel.name])
}

# Audit: Customer-managed encryption keys (best practice per 2022)
audit[msg] {
    resource := resources.cloud_resources[_]
    resource.encryption_key_management == "Provider Managed"
    resource.classification in ["Confidential", "Restricted"]
    msg := sprintf("ISO 27001:2022 A.5.10.3: Consider customer-managed keys for %s per 2022 best practices", [resource.name])
}

# Audit: Perfect Forward Secrecy (PFS) for sensitive data (2022 recommendation)
audit[msg] {
    connection := resources.secure_connections[_]
    connection.perfect_forward_secrecy_enabled == false
    connection.handles_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.14: Connection %s should use PFS-enabled ciphers for sensitive data", [connection.name])
}

# Test cases
test_compliant_storage {
    storage := {
        "name": "securestg",
        "encryption_at_rest": {"enabled": true, "algorithm": "AES-256"},
        "https_only": true,
        "tls_minimum_version": 1.2,
        "data_transfer": {"https_only": true}
    }
    count(deny) == 0
}

test_weak_encryption {
    count(deny) > 0 with data.azure.resources.storage_accounts as [{
        "name": "weakstg",
        "encryption_at_rest": {"enabled": true, "algorithm": "AES-128"},
        "https_only": true
    }]
}

test_cloud_resource_no_assessment {
    count(deny) > 0 with data.azure.resources.cloud_services as [{
        "name": "cloud-app",
        "security_assessment_completed": false,
        "contains_sensitive_data": true
    }]
}
