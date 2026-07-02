resource "wiz_cloud_configuration_rule" "aws_kms_key_expiration" {
  name                     = "${var.prefix} - KMS imported key material expiring soon"
  description              = "Identifies KMS keys with imported key material (Origin: EXTERNAL) that will expire within 5 days. Keys without an expiration date are skipped."
  target_native_types      = ["encryptionKey"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **KMS > Customer managed keys**.
    2. Select the affected key.
    3. Import new key material before the current material expires.
    4. Use the AWS CLI to re-import:
       ```
       aws kms import-key-material \
           --key-id <key-id> \
           --import-token <import-token> \
           --encrypted-key-material <key-material> \
           --expiration-model KEY_MATERIAL_EXPIRES \
           --valid-to <new-expiration-date>
       ```
    5. Alternatively, set `--expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE` to remove the expiration.
  EOT

  opa_policy = file("${path.module}/rego/aws_kms_key_expiration.rego")
}
