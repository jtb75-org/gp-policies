resource "wiz_cloud_configuration_rule" "aws_vendor_access_key_older_than_60_days" {
  name                     = "${var.prefix} - Vendor access keys should be rotated every 60 days"
  description              = "Identifies AWS IAM users tagged as type=vendor with active access keys that have not been rotated in the last 60 days."
  target_native_types      = ["user"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to IAM.
    2. Select the affected vendor user.
    3. Go to the **Security credentials** tab.
    4. Under **Access keys**, create a new access key.
    5. Provide the new key to the vendor and confirm they have updated their configuration.
    6. Deactivate and then delete the old access key.
  EOT

  opa_policy = file("${path.module}/rego/aws_vendor_access_key_rotation.rego")
}
