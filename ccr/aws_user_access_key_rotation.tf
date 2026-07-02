resource "wiz_cloud_configuration_rule" "aws_user_access_key_older_than_30_days" {
  name                     = "${var.prefix} - User access keys should be rotated every 30 days"
  description              = "Identifies AWS IAM users (human) with active access keys that have not been rotated in the last 30 days."
  target_native_types      = ["user"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to IAM.
    2. Select the affected user.
    3. Go to the **Security credentials** tab.
    4. Under **Access keys**, create a new access key.
    5. Update any local configurations using the old key with the new key.
    6. Deactivate and then delete the old access key.
  EOT

  opa_policy = file("${path.module}/rego/aws_user_access_key_rotation.rego")
}
