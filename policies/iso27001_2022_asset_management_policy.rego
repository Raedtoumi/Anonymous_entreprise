# ISO/IEC 27001:2022 Control 5.4 - Asset Management
# Policy: Inventory, ownership, and protection of information assets

package iso27001_2022.asset_management

import data.assets
import future.keywords.contains
import future.keywords.in

# ISO 27001:2022 A.5.4 - Information Assets (NEW emphasis)
# All assets must be inventoried and classified
deny[msg] {
    asset := assets.all_assets[_]
    asset.in_inventory == false
    msg := sprintf("ISO 27001:2022 A.5.4: Asset %s not in inventory - violates asset management", [asset.asset_id])
}

# ISO 27001:2022 A.5.4 - Asset Classification (mandatory)
deny[msg] {
    asset := assets.all_assets[_]
    classification := asset.classification
    not classification
    msg := sprintf("ISO 27001:2022 A.5.4: Asset %s (%s) not classified - violates asset management", [asset.asset_id, asset.asset_type])
}

# ISO 27001:2022 A.5.4 - Asset Ownership (mandatory)
deny[msg] {
    asset := assets.all_assets[_]
    asset.criticality in ["Critical", "High"]
    owner := asset.owner
    not owner
    msg := sprintf("ISO 27001:2022 A.5.4: Critical asset %s has no owner - violates asset management", [asset.asset_id])
}

# ISO 27001:2022 A.5.4 - Asset Lifecycle Management
deny[msg] {
    asset := assets.all_assets[_]
    asset.lifecycle_stage == "End of Life"
    asset.decommissioned == false
    asset.data_securely_deleted == false
    msg := sprintf("ISO 27001:2022 A.5.4: Asset %s in EOL stage but not decommissioned securely", [asset.asset_id])
}

# ISO 27001:2022 A.5.4 - Asset Return/Recovery
deny[msg] {
    asset := assets.mobile_devices[_]
    asset.employee_departed == true
    asset.device_recovered == false
    asset.days_since_departure > 7
    msg := sprintf("ISO 27001:2022 A.5.4: Device %s not recovered from departed employee (overdue)", [asset.device_id])
}

# ISO 27001:2022 A.5.4 - Sensitive Asset Tracking
deny[msg] {
    asset := assets.sensitive_assets[_]
    asset.location_tracked == false
    asset.contains_sensitive_data == true
    msg := sprintf("ISO 27001:2022 A.5.4: Sensitive asset %s location not tracked - violates asset protection", [asset.asset_id])
}

# ISO 27001:2022 A.5.4 - Asset Removal Control
deny[msg] {
    asset := assets.all_assets[_]
    asset.physical_removal_attempted == true
    asset.removal_authorized == false
    msg := sprintf("ISO 27001:2022 A.5.4: Unauthorized asset removal attempt for %s", [asset.asset_id])
}

# Audit: Asset inventory review not completed
audit[msg] {
    organization := assets.organization[_]
    organization.last_inventory_review > 180
    msg := "ISO 27001:2022 A.5.4: Asset inventory review overdue (recommend quarterly)"
}

# Test cases
test_compliant_asset {
    asset := {
        "asset_id": "SRV-001",
        "asset_type": "Server",
        "in_inventory": true,
        "classification": "Confidential",
        "owner": "john@contoso.com",
        "lifecycle_stage": "Active",
        "location_tracked": true
    }
    count(deny) == 0
}

test_unclassified_asset {
    count(deny) > 0 with data.assets.all_assets as [{
        "asset_id": "SRV-001",
        "asset_type": "Server",
        "in_inventory": true
    }]
}
