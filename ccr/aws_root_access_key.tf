resource "wiz_cloud_configuration_rule" "aws_root_access_key" {
  name                     = "${var.prefix} - Root account with programmatic access key"
  description              = "Identifies AWS root accounts that have an active programmatic access key attached."
  target_native_types      = ["rootUser"]
  severity                 = "CRITICAL"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console as the root user.
    2. Navigate to **Security credentials** (under the account dropdown).
    3. Under **Access keys**, delete any active access keys.
    4. Use IAM roles or IAM users with least-privilege policies for programmatic access.
  EOT

  opa_policy       = file("${path.module}/rego/aws_root_access_key.rego")
  scope_project_id = local.scope_project_id
}
