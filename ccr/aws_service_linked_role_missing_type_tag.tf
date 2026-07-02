resource "wiz_cloud_configuration_rule" "aws_service_linked_role_missing_type_tag" {
  name                     = "${var.prefix} - Service/service-linked roles missing type:service tag"
  description              = "Identifies IAM roles with path /service-role/ or /aws-service-role/ that are missing a type:service tag."
  target_native_types      = ["role"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Roles**.
    2. Select the affected role.
    3. Under the **Tags** tab, add a tag with key `type` and value `service`.
    4. Note: Service-linked roles may have restricted tag editing. If so, contact your cloud platform team.
  EOT

  opa_policy       = file("${path.module}/rego/aws_service_linked_role_missing_type_tag.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
