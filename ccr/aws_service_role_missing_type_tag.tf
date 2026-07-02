resource "wiz_cloud_configuration_rule" "aws_service_role_missing_type_tag" {
  name                     = "${var.prefix} - Service roles must have a valid type tag"
  description              = "Identifies IAM roles matching known service role names that are missing a type tag or have an unrecognized type tag value."
  target_native_types      = ["role"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to IAM.
    2. Select the affected role.
    3. Go to the **Tags** tab.
    4. Add or correct the **type** tag with one of the valid values: `user`, `service`, `vendor`.
  EOT

  opa_policy       = file("${path.module}/rego/aws_service_role_missing_type_tag.rego")
  scope_project_id = local.scope_project_id
}
