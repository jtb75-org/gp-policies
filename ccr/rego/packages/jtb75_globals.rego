# Custom Rego packages must use the "customPackage.<name>" namespace.
# This package is imported by rules using:
#   import data.customPackage.jtb75Globals as globals
package customPackage.jtb75Globals

# AWS accounts that belong to our organization.
# These are accounts managed internally and connected to Wiz.
trusted_internal_accounts := {
    "123456789012",
    "234567890123",
    "494378024839",
}

# AWS accounts owned by trusted third parties.
# These are external accounts we have explicitly approved for
# cross-account access (e.g., vendor or partner accounts).
trusted_external_accounts := {
    "345678901234",
}

# Combined set of all trusted accounts (internal + external).
# The "|" operator performs a set union, merging both sets into one.
# Individual rules can reference either the specific lists above
# or this combined set depending on their needs.
trusted_accounts := trusted_internal_accounts | trusted_external_accounts

# Access key rotation thresholds in days.
# Service accounts have a longer rotation window than human users.
service_key_max_age_days := 90
service_key_warning_days := 85
user_key_max_age_days := 30
user_key_warning_days := 25
vendor_key_max_age_days := 60
vendor_key_warning_days := 55

# Root account usage detection thresholds.
# account_min_age_days: skip accounts younger than this (allows setup time)
# root_usage_lookback_days: alert if root was used within this many days
account_min_age_days := 15
root_usage_lookback_days := 1

# Minimum RDS backup retention period in days.
rds_backup_retention_days := 35

# KMS key expiration and rotation warning thresholds in days.
kms_expiration_warning_days := 5
kms_rotation_warning_days := 5

# Root MFA grace period — new accounts get this many days before MFA is required.
root_mfa_grace_days := 10

# Known support role names.
# Used to identify roles that should have a valid "type" tag.
# Role names are matched case-sensitively against this set.
kbs_support_roles := {
    "KBSSupportRole",
    "KBSSupportAdmin",
    "KBSSupportReadOnly",
    "Webserver-Role",
}

# Known vendor role names.
# Roles owned by external vendors that must have a valid "type" tag.
kbs_vendor_roles := {
    "VendorMonitoringRole",
    "VendorBackupAgent",
    "ThirdPartyAuditRole",
}

# Known service role names.
# Roles used by internal services that must have a valid "type" tag.
kbs_service_roles := {
    "AppDeploymentRole",
    "DataPipelineExecutor",
    "CICDServiceRole",
}
