resource "wiz_cloud_configuration_rule" "aws_s3_bucket_untrusted_sharing" {
  name                     = "${var.prefix} - S3 buckets shared with untrusted accounts"
  description              = "Identifies S3 buckets shared with AWS accounts not in the organization or trusted accounts list via bucket policy, ACL, or inventory configuration."
  target_native_types      = ["bucket"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **S3**.
    2. Select the affected bucket.
    3. Review the **Permissions** tab:
       - **Bucket policy**: Remove or update statements granting access to untrusted account ARNs.
       - **Access control list (ACL)**: Remove grants to untrusted accounts or public access groups.
    4. Review **Management > Inventory configurations** for destinations pointing to untrusted accounts.
    5. If the bucket is public, enable **Block Public Access** settings.
  EOT

  opa_policy       = file("${path.module}/rego/aws_s3_bucket_untrusted_sharing.rego")
  scope_project_id = local.scope_project_id
}
