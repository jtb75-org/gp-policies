resource "wiz_cloud_configuration_rule" "aws_root_account_usage" {
  name                     = "${var.prefix} - Root account used in the last day"
  description              = "Identifies AWS root accounts that have been used in the last day. Accounts younger than 15 days are skipped to allow the cloud platform team time to set up automation."
  target_native_types      = ["rootUser"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Identify why the root account was used and whether it was authorized.
    2. If the root account was used for routine tasks, delegate those tasks to an IAM user or role with appropriate permissions.
    3. Ensure root account access keys are disabled or deleted.
    4. Verify that MFA is enabled on the root account.
    5. Review CloudTrail logs for the root account activity to determine what actions were performed.
  EOT

  opa_policy       = file("${path.module}/rego/aws_root_account_usage.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
