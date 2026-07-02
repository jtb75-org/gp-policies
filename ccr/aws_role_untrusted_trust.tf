resource "wiz_cloud_configuration_rule" "aws_role_untrusted_trust" {
  name                     = "${var.prefix} - IAM roles with untrusted account trust relationships"
  description              = "Identifies IAM roles with trust policies that allow assumption by AWS accounts not in the organization or trusted accounts list."
  target_native_types      = ["role"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Roles**.
    2. Select the affected role.
    3. Choose the **Trust relationships** tab, then **Edit trust policy**.
    4. Remove any untrusted account ARNs from the `Principal.AWS` field.
    5. If the role is publicly assumable (`"Principal": "*"`), restrict it to specific trusted accounts.
    6. If the account should be trusted, add it to the trusted accounts list in the globals package.
  EOT

  opa_policy       = file("${path.module}/rego/aws_role_untrusted_trust.rego")
  scope_project_id = local.scope_project_id
}
