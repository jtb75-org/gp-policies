resource "wiz_cloud_configuration_rule" "aws_support_saml_role_missing_type_tag" {
  name                     = "${var.prefix} - Support SAML roles missing type:support tag"
  description              = "Identifies IAM roles with 'support-saml' in their name that are missing a type:support tag."
  target_native_types      = ["role"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Roles**.
    2. Select the affected role.
    3. Under the **Tags** tab, add a tag with key `type` and value `support`.
  EOT

  opa_policy       = file("${path.module}/rego/aws_support_saml_role_missing_type_tag.rego")
  scope_project_id = local.scope_project_id
}
