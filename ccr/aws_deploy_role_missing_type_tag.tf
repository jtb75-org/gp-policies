resource "wiz_cloud_configuration_rule" "aws_deploy_role_missing_type_tag" {
  name                     = "${var.prefix} - Deploy roles missing type:deployment tag"
  description              = "Identifies IAM roles with 'deploy-' in their name that are missing a type:deployment tag."
  target_native_types      = ["role"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Roles**.
    2. Select the affected role.
    3. Under the **Tags** tab, add a tag with key `type` and value `deployment`.
  EOT

  opa_policy       = file("${path.module}/rego/aws_deploy_role_missing_type_tag.rego")
  scope_project_id = local.scope_project_id
}
