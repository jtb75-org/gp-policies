resource "wiz_cloud_configuration_rule" "aws_missing_type_tag" {
  name                     = "${var.prefix} - IAM users must have a valid type tag"
  description              = "Identifies AWS IAM users without a type tag or with an unrecognized type tag value. Valid values are: user, service, vendor."
  target_native_types      = ["user"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to IAM.
    2. Select the affected user.
    3. Go to the **Tags** tab.
    4. Add or correct the **type** tag with one of the valid values: `user`, `service`, `vendor`.
  EOT

  opa_policy = file("${path.module}/rego/aws_missing_type_tag.rego")
}
