# =============================================================================
# Response Action Catalog Items — Custom Outpost Lite remediation actions
# =============================================================================

# --- Tag consumer roles with type:consumer ---

resource "wiz_file_upload" "tag_consumer_role" {
  filename = "tag-consumer-role.py"
  content  = file("${path.module}/../remediation-infra/custom-actions/tag-consumer-role.py")
}

resource "wiz_response_action_catalog_item" "tag_consumer_role" {
  name           = "JTB75 - Tag consumer role"
  description    = "Auto-tag IAM roles containing 'consumer' in the name with type:consumer."
  cloud_platform = "AWS"

  cloud_provider_permissions = [
    "iam:GetRole",
    "iam:TagRole",
  ]

  targets {
    cloud_configuration_rule = [
      wiz_cloud_configuration_rule.aws_consumer_role_missing_type_tag.id,
    ]
  }

  file_upload = wiz_file_upload.tag_consumer_role.id
}

# --- Remove untrusted principals from role trust policies ---

resource "wiz_file_upload" "remove_untrusted_trust" {
  filename = "remove-untrusted-trust.py"
  content  = file("${path.module}/../remediation-infra/custom-actions/remove-untrusted-trust.py")
}

resource "wiz_response_action_catalog_item" "remove_untrusted_trust" {
  name           = "JTB75 - Remove untrusted trusts from roles"
  description    = "Remove untrusted AWS principals from IAM role trust policies. Preserves trusted accounts and service principals."
  cloud_platform = "AWS"

  cloud_provider_permissions = [
    "iam:GetRole",
    "iam:UpdateAssumeRolePolicy",
    "iam:TagRole",
  ]

  revertible = true

  revert_cloud_provider_permissions = [
    "iam:GetRole",
    "iam:UpdateAssumeRolePolicy",
    "iam:UntagRole",
  ]

  targets {
    cloud_configuration_rule = [
      wiz_cloud_configuration_rule.aws_role_untrusted_trust.id,
    ]
  }

  file_upload = wiz_file_upload.remove_untrusted_trust.id
}

# --- Deactivate stale access keys ---

resource "wiz_file_upload" "deactivate_stale_access_keys" {
  filename = "deactivate-stale-access-keys.py"
  content  = file("${path.module}/../remediation-infra/custom-actions/deactivate-stale-access-keys.py")
}

resource "wiz_response_action_catalog_item" "deactivate_stale_access_keys" {
  name           = "JTB75 - Deactivate stale access keys"
  description    = "Deactivate IAM access keys that have exceeded the rotation threshold for the user's type (service=90d, vendor=60d, user/default=30d)."
  cloud_platform = "AWS"

  cloud_provider_permissions = [
    "iam:ListAccessKeys",
    "iam:GetAccessKeyLastUsed",
    "iam:UpdateAccessKey",
    "iam:ListUserTags",
    "iam:TagUser",
  ]

  revertible = true

  revert_cloud_provider_permissions = [
    "iam:UpdateAccessKey",
    "iam:ListUserTags",
    "iam:UntagUser",
  ]

  targets {
    cloud_configuration_rule = [
      wiz_cloud_configuration_rule.aws_service_access_key_older_than_90_days.id,
      wiz_cloud_configuration_rule.aws_user_access_key_older_than_30_days.id,
      wiz_cloud_configuration_rule.aws_vendor_access_key_older_than_60_days.id,
      wiz_cloud_configuration_rule.aws_untagged_access_key_older_than_30_days.id,
    ]
  }

  file_upload = wiz_file_upload.deactivate_stale_access_keys.id
}

# --- Quarantine S3 Malware ---

resource "wiz_file_upload" "quarantine_s3_malware" {
  filename = "quarantine-s3-malware.py"
  content  = file("${path.module}/../remediation-infra/custom-actions/quarantine-s3-malware.py")
}

resource "wiz_response_action_catalog_item" "quarantine_s3_malware" {
  name           = "JTB75 - Quarantine S3 malware"
  description    = "Quarantine malicious files detected in S3 buckets by moving them to a secure quarantine bucket and deleting the original."
  cloud_platform = "AWS"

  cloud_provider_permissions = [
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:PutObject",
    "s3:ListBucket",
    "s3:ListBucketVersions"
  ]

  revertible = true

  revert_cloud_provider_permissions = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket"
  ]

  targets {
    graph_entity_native_type = ["bucket"]
  }

  file_upload = wiz_file_upload.quarantine_s3_malware.id
}
