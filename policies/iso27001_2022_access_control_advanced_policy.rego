# ISO/IEC 27001:2022 Control 5.5 - Access Control (Advanced)
# Policy: User access rights, authorization, and segregation of duties

package iso27001_2022.access_control_advanced

import data.access_control
import future.keywords.contains
import future.keywords.in

# ISO 27001:2022 A.5.5.1 - User Access Control (Authorization)
deny[msg] {
    user := access_control.users[_]
    user.access_rights_reviewed == false
    user.employment_status == "Active"
    msg := sprintf("ISO 27001:2022 A.5.5.1: User %s access rights not reviewed - violates authorization control", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.5.1 - Approval for Access Rights
deny[msg] {
    user := access_control.users[_]
    user.new_access_request == true
    user.manager_approval == false
    msg := sprintf("ISO 27001:2022 A.5.5.1: User %s new access request lacks manager approval", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.5.2 - Privileged Access Rights (Segregation of Duties)
deny[msg] {
    user := access_control.users[_]
    conflicting_roles := identify_conflicting_roles(user.roles)
    count(conflicting_roles) > 0
    msg := sprintf("ISO 27001:2022 A.5.5.2: User %s has conflicting roles: %v - violates segregation of duties", [user.userPrincipalName, conflicting_roles])
}

# ISO 27001:2022 A.5.5.3 - User Access Review (Annual minimum)
deny[msg] {
    user := access_control.users[_]
    user.employment_status == "Active"
    review := user.last_access_review
    not review
    days_active := (now - user.created_date) / 86400
    days_active > 365
    msg := sprintf("ISO 27001:2022 A.5.5.3: User %s access review overdue (>1 year) - violates periodic review", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.5.4 - Access Rights Modification
deny[msg] {
    access_log := access_control.access_logs[_]
    access_log.rights_removed == true
    access_log.removal_documented == false
    msg := sprintf("ISO 27001:2022 A.5.5.4: Access right removal not documented for user %s", [access_log.user])
}

# ISO 27001:2022 A.5.5.4 - Provisioning & De-provisioning
deny[msg] {
    user := access_control.users[_]
    user.employment_status == "Terminated"
    user.account_disabled == false
    days_since_termination := (now - user.termination_date) / 86400
    days_since_termination > 1
    msg := sprintf("ISO 27001:2022 A.5.5.4: Terminated user %s account not disabled immediately", [user.userPrincipalName])
}

# ISO 27001:2022 A.5.5.1 - User Entitlement Bloat
deny[msg] {
    user := access_control.users[_]
    user.role_count > 10
    msg := sprintf("ISO 27001:2022 A.5.5.1: User %s has %d roles (recommend max 5) - violates least privilege", [user.userPrincipalName, user.role_count])
}

# ISO 27001:2022 A.5.5.2 - Service Account Access Control
deny[msg] {
    service := access_control.service_accounts[_]
    service.password_shared == true
    msg := sprintf("ISO 27001:2022 A.5.5.2: Service account %s password is shared - violates access control", [service.account_name])
}

# ISO 27001:2022 A.5.5.1 - Emergency Access Procedures
deny[msg] {
    organization := access_control.organization[_]
    organization.emergency_access_procedure == false
    msg := sprintf("ISO 27001:2022 A.5.5.1: No emergency access procedures defined - violates break-glass controls")
}

# ISO 27001:2022 A.5.5.3 - Supplier Access Review
deny[msg] {
    supplier := access_control.suppliers[_]
    supplier.system_access == true
    supplier.access_last_reviewed > 365
    msg := sprintf("ISO 27001:2022 A.5.5.3: Supplier %s access review overdue (>1 year)", [supplier.name])
}

# Helper: Identify conflicting roles (SOD violation)
identify_conflicting_roles(roles) = conflicts {
    has_requester := roles[_] == "Requester"
    has_requester
    conflicts := [role | role := roles[_]; conflict_role := ["Approver", "Reviewer"][_]; role == conflict_role]
}

# Audit: Privileged access not monitored
audit[msg] {
    user := access_control.users[_]
    user.role in ["Global Administrator", "Security Administrator"]
    user.access_monitored == false
    msg := sprintf("ISO 27001:2022 A.5.5: Privileged user %s not monitored - recommend monitoring", [user.userPrincipalName])
}

# Test cases
test_compliant_user {
    user := {
        "userPrincipalName": "user@contoso.com",
        "access_rights_reviewed": true,
        "roles": ["User", "Team Lead"],
        "role_count": 2,
        "last_access_review": "2026-05-01",
        "employment_status": "Active"
    }
    count(deny) == 0
}

test_no_access_review {
    user := {
        "userPrincipalName": "user@contoso.com",
        "access_rights_reviewed": false,
        "employment_status": "Active"
    }
    count(deny) > 0
}

test_terminated_user_active {
    user := {
        "userPrincipalName": "olduser@contoso.com",
        "employment_status": "Terminated",
        "account_disabled": false,
        "termination_date": 1704000000
    }
    count(deny) > 0
}
