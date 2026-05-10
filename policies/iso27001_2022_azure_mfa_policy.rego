# ISO/IEC 27001:2022 Control 5.2 - Information Security Policies (User Authentication)
# ISO/IEC 27001:2022 Control 5.15 - Access Control (Authentication & Authorization)
# ISO/IEC 27001:2022 Control 5.16 - Identity Management (User Registration/De-registration)
# Policy: Multi-factor authentication and strong credential management for Azure/M365

package iso27001_2022.authentication

import data.azure.identities
import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ISO 27001:2022 A.5.15.2.1 - User Registration and De-registration
deny[msg] {
    user := identities.users[_]
    user.mfa_enabled == false
    user.account_enabled == true
    msg := sprintf("ISO 27001:2022 A.5.15.2.1: User %s missing MFA - violates authentication controls", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.15.3 - Password Management
# Enhanced password requirements per 2022 standard
deny[msg] {
    user := identities.users[_]
    user.password_policy.minimum_length < 12
    msg := sprintf("ISO 27001:2022 A.5.15.3: User %s has minimum password length %d, requires minimum 12 characters", [user.userPrincipalName, user.password_policy.minimum_length])
}

deny[msg] {
    user := identities.users[_]
    user.password_policy.complexity_required == false
    user.account_type in ["User", "Administrator"]
    msg := sprintf("ISO 27001:2022 A.5.15.3: User %s password policy does not enforce complexity requirements", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.15.6 - Removal or Adjustment of Access Rights
# Enhanced de-registration requirement
deny[msg] {
    user := identities.users[_]
    user.account_enabled == true
    days_since_signin := (time.now_ns() / 1000000000 - user.lastSignInDateTime) / 86400
    days_since_signin > 60
    user.employment_status != "Terminated"
    msg := sprintf("ISO 27001:2022 A.5.15.6: User %s inactive %d days but account still active - violates de-registration control", [user.userPrincipalName, days_since_signin])
}

# ISO 27001:2022 NEW - A.5.16.1 - Identity Management (New in 2022)
# Users must have unique identities with audit trail
deny[msg] {
    user := identities.users[_]
    not user.last_access_review
    msg := sprintf("ISO 27001:2022 A.5.16.1: User %s missing access review - violates 2022 identity management requirement", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.18.1 - Monitoring (Measurement & Metrics)
# 2022 standard requires monitoring of authentication failures
deny[msg] {
    user := identities.users[_]
    user.failed_signin_attempts > 10
    user.account_locked_status == false
    msg := sprintf("ISO 27001:2022 A.5.18.1: User %s has %d failed signin attempts but account not locked", [user.userPrincipalName, user.failed_signin_attempts])
}

# ISO 27001:2022 A.5.23 - Cloud Security (NEW in 2022)
# Cloud identity security must meet baseline
deny[msg] {
    user := identities.users[_]
    user.cloud_identity == true
    user.conditional_access_enabled == false
    msg := sprintf("ISO 27001:2022 A.5.23: Cloud user %s missing Conditional Access - violates 2022 cloud security controls", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.16.2 - Privileged Access Management (enhanced in 2022)
deny[msg] {
    user := identities.users[_]
    user.role in ["Global Administrator", "Security Administrator"]
    user.pim_eligible == false
    msg := sprintf("ISO 27001:2022 A.5.16.2: Privileged user %s not managed via PIM - violates 2022 privileged access controls", [user.userPrincipalName])
}

# Audit recommendation per 2022 standard
audit[msg] {
    user := identities.users[_]
    user.passwordless_signin_enabled == false
    user.mfa_method != "Windows Hello"
    user.mfa_method != "FIDO2"
    msg := sprintf("ISO 27001:2022 A.5.15.3: User %s should use passwordless methods for enhanced security (2022 best practice)", [user.userPrincipalName])
}

# Test cases
test_compliant_user {
    user := {
        "userPrincipalName": "user@contoso.com",
        "mfa_enabled": true,
        "account_enabled": true,
        "password_policy": {"minimum_length": 12, "complexity_required": true},
        "lastSignInDateTime": 1715000000,
        "employment_status": "Active",
        "last_access_review": "2026-05-01",
        "failed_signin_attempts": 0,
        "cloud_identity": true,
        "conditional_access_enabled": true,
        "role": "User"
    }
    count(deny) == 0
}

test_no_mfa {
    count(deny) > 0 with data.azure.identities.users as [{
        "userPrincipalName": "user@contoso.com",
        "mfa_enabled": false,
        "account_enabled": true
    }]
}
