resource "wiz_cloud_configuration_rule" "aws_vendor_role_auto_tag" {
  name                     = "${var.prefix} - Vendor roles missing type:vendor tag based on trust relationship"
  description              = "Identifies IAM roles that trust accounts in the trusted external accounts list but are missing a type:vendor tag."
  target_native_types      = ["role"]
  severity                 = "INFORMATIONAL"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Roles**.
    2. Select the affected role.
    3. Under the **Tags** tab, add a tag with key `type` and value `vendor`.
  EOT

  opa_policy       = file("${path.module}/rego/aws_vendor_role_auto_tag.rego")
  scope_project_id = local.scope_project_id
}
