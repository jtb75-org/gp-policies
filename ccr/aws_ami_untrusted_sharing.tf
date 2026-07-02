resource "wiz_cloud_configuration_rule" "aws_ami_untrusted_sharing" {
  name                     = "${var.prefix} - EC2 AMIs shared with untrusted accounts"
  description              = "Identifies EC2 AMIs (machine images) shared publicly or with AWS accounts not in the organization or trusted accounts list."
  target_native_types      = ["ami"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **EC2 > AMIs**.
    2. Select the affected AMI.
    3. Choose **Actions > Edit AMI permissions**.
    4. Change **AMI availability** from **Public** to **Private** if applicable.
    5. Remove any untrusted account IDs from the shared accounts list.

    **Via CLI:**
    ```
    aws ec2 modify-image-attribute \
        --image-id <ami-id> \
        --launch-permission "Remove=[{UserId=<untrusted-account-id>}]"
    ```

    To make a public AMI private:
    ```
    aws ec2 modify-image-attribute \
        --image-id <ami-id> \
        --launch-permission "Remove=[{Group=all}]"
    ```
  EOT

  opa_policy       = file("${path.module}/rego/aws_ami_untrusted_sharing.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
