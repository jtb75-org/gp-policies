resource "wiz_cloud_configuration_rule" "aws_administrator_role_missing_type_tag" {
  name                     = "${var.prefix} - Administrator role missing type:support tag"
  description              = "Identifies the Administrator IAM role when it is missing a type:support tag."
  target_native_types      = ["role"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **IAM > Roles**.
    2. Select the **Administrator** role.
    3. Under the **Tags** tab, add a tag with key `type` and value `support`.
  EOT

  opa_policy = file("${path.module}/rego/aws_administrator_role_missing_type_tag.rego")
}
