resource "wiz_cloud_configuration_rule" "aws_root_missing_mfa" {
  name                     = "${var.prefix} - Root account missing MFA"
  description              = "Identifies AWS root accounts without MFA enabled. Accounts younger than 10 days are exempt to allow for account build automation."
  target_native_types      = ["rootUser"]
  severity                 = "CRITICAL"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console as the root user.
    2. Navigate to **Security credentials** (under the account dropdown).
    3. Under **Multi-factor authentication (MFA)**, choose **Assign MFA device**.
    4. Follow the prompts to configure a virtual or hardware MFA device.
    5. Verify MFA is working by signing out and signing back in.
  EOT

  opa_policy       = file("${path.module}/rego/aws_root_missing_mfa.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
