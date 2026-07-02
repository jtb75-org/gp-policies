resource "wiz_cloud_configuration_rule" "aws_apigateway_no_authorization" {
  name                     = "${var.prefix} - API Gateway methods without authorization"
  description              = "Identifies API Gateway deployments with methods that have no authorization configured and are missing the authentication:kochid exemption tag."
  target_native_types      = ["apiGateway"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **API Gateway**.
    2. Select the affected API.
    3. For each method with Authorization Type "NONE":
       a. Select the method and choose **Method Request**.
       b. Set **Authorization** to an appropriate authorizer (e.g., AWS IAM, Cognito, Lambda).
    4. Alternatively, if authentication is handled externally via KochID, add the tag `authentication:kochid` to the API Gateway.
    5. **Redeploy** the API to apply changes.
  EOT

  opa_policy       = file("${path.module}/rego/aws_apigateway_no_authorization.rego")
  scope_project_id = local.scope_project_id
}
