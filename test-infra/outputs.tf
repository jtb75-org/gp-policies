# =============================================================================
# Outputs — Resource identifiers for reference and verification
# =============================================================================

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

# IAM Roles
output "role_arns" {
  value = {
    consumer_no_tag     = aws_iam_role.test_consumer_no_tag.arn
    deploy_no_tag       = aws_iam_role.test_deploy_no_tag.arn
    support_saml_no_tag = aws_iam_role.test_support_saml_no_tag.arn
    administrator       = aws_iam_role.test_administrator_no_tag.arn
    service_path_no_tag = aws_iam_role.test_service_path_no_tag.arn
    kbs_support         = aws_iam_role.test_kbs_support_no_tag.arn
    kbs_vendor          = aws_iam_role.test_kbs_vendor_no_tag.arn
    kbs_service         = aws_iam_role.test_kbs_service_no_tag.arn
    public_trust        = aws_iam_role.test_public_trust.arn
    vendor_auto_tag     = aws_iam_role.test_vendor_auto_tag.arn
  }
}

# IAM Users
output "user_arns" {
  value = {
    no_type_tag    = aws_iam_user.test_no_type_tag.arn
    bad_type_tag   = aws_iam_user.test_bad_type_tag.arn
    managed_policy = aws_iam_user.test_managed_policy.arn
    service_user   = aws_iam_user.test_service_user.arn
    vendor_user    = aws_iam_user.test_vendor_user.arn
    human_user     = aws_iam_user.test_human_user.arn
    untagged_user  = aws_iam_user.test_untagged_user.arn
  }
}

# Access keys (IDs only — secrets are sensitive)
output "access_key_ids" {
  value = {
    service  = aws_iam_access_key.test_service_key.id
    vendor   = aws_iam_access_key.test_vendor_key.id
    human    = aws_iam_access_key.test_human_key.id
    untagged = aws_iam_access_key.test_untagged_key.id
  }
}

# S3 Buckets
output "bucket_names" {
  value = {
    untrusted_sharing    = aws_s3_bucket.test_untrusted_sharing.id
    classified_no_enc    = aws_s3_bucket.test_classified_no_encryption.id
    classified_encrypted = aws_s3_bucket.test_classified_encrypted.id
    trusted_sharing      = aws_s3_bucket.test_trusted_sharing.id
  }
}

# Snapshots
output "snapshot_ids" {
  value = {
    shared_untrusted = aws_ebs_snapshot.test_snapshot.id
    clean            = aws_ebs_snapshot.test_snapshot_clean.id
  }
}

# RDS
output "rds_identifiers" {
  value = {
    low_retention  = aws_db_instance.test_low_retention.identifier
    good_retention = aws_db_instance.test_good_retention.identifier
  }
}

# API Gateways
output "api_gateway_ids" {
  value = {
    no_auth       = aws_api_gateway_rest_api.test_no_auth.id
    kochid_exempt = aws_api_gateway_rest_api.test_kochid_exempt.id
    iam_auth      = aws_api_gateway_rest_api.test_iam_auth.id
  }
}

# Malware Testing
output "malware_bucket_name" {
  value = aws_s3_bucket.test_malware.id
}

output "malware_file_hashes" {
  value = {
    "eicar_test_1.txt" = {
      md5    = md5(aws_s3_object.malware_file_1.content)
      sha1   = sha1(aws_s3_object.malware_file_1.content)
      sha256 = sha256(aws_s3_object.malware_file_1.content)
    }
    "eicar_test_2.txt" = {
      md5    = md5(aws_s3_object.malware_file_2.content)
      sha1   = sha1(aws_s3_object.malware_file_2.content)
      sha256 = sha256(aws_s3_object.malware_file_2.content)
    }
    "eicar_test_3.txt" = {
      md5    = md5(aws_s3_object.malware_file_3.content)
      sha1   = sha1(aws_s3_object.malware_file_3.content)
      sha256 = sha256(aws_s3_object.malware_file_3.content)
    }
  }
}
