resource "wiz_cloud_configuration_rule" "aws_vendor_access_key_older_than_55_days" {
  name                     = "${var.prefix} - Vendor access keys approaching 60-day rotation limit (55 days)"
  description              = "Identifies AWS IAM users tagged as type=vendor with active access keys that have not been rotated in the last 55 days."
  target_native_types      = ["user"]
  severity                 = "INFORMATIONAL"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to IAM.
    2. Select the affected vendor user.
    3. Go to the **Security credentials** tab.
    4. Under **Access keys**, create a new access key.
    5. Provide the new key to the vendor and confirm they have updated their configuration.
    6. Deactivate and then delete the old access key.
  EOT

  opa_policy       = file("${path.module}/rego/aws_vendor_access_key_rotation_warning.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
