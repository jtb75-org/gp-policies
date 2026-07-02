resource "wiz_cloud_configuration_rule" "aws_user_aws_managed_policy" {
  name                     = "${var.prefix} - IAM users with AWS managed policies attached"
  description              = "Identifies IAM users with AWS managed policies attached. AWS managed policies are overly permissive and users should have customer-managed policies scoped to their specific needs."
  target_native_types      = ["user"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Users**.
    2. Select the affected user.
    3. Under the **Permissions** tab, identify any AWS managed policies (ARN starts with `arn:aws:iam::aws:policy/`).
    4. Remove the AWS managed policies.
    5. Create and attach a customer-managed policy scoped to the specific actions and resources the user needs.
  EOT

  opa_policy       = file("${path.module}/rego/aws_user_aws_managed_policy.rego")
  scope_project_id = local.scope_project_id
}
