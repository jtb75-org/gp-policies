resource "wiz_cloud_configuration_rule" "aws_service_access_key_older_than_85_days" {
  name                     = "${var.prefix} - Service account access keys approaching 90-day rotation limit (85 days)"
  description              = "Identifies AWS IAM service accounts with active access keys that have not been rotated in the last 85 days."
  target_native_types      = ["user"]
  severity                 = "INFORMATIONAL"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to IAM.
    2. Select the affected service account.
    3. Go to the **Security credentials** tab.
    4. Under **Access keys**, create a new access key.
    5. Update all applications and services using the old key with the new key.
    6. Deactivate and then delete the old access key.
  EOT

  opa_policy       = file("${path.module}/rego/aws_service_access_key_rotation_warning.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
