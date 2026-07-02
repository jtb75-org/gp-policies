resource "wiz_cloud_configuration_rule" "aws_kms_key_rotation_warning" {
  name                     = "${var.prefix} - KMS key rotation approaching"
  description              = "Identifies KMS keys with automatic rotation scheduled within 5 days. Keys without rotation enabled are skipped."
  target_native_types      = ["encryptionKey"]
  severity                 = "INFORMATIONAL"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Verify that the key rotation is expected and will complete automatically.
    2. If on-demand rotation is needed sooner, use:
       ```
       aws kms rotate-key-on-demand --key-id <key-id>
       ```
    3. Ensure any applications using this key are compatible with rotated key material.
    4. Review the rotation period if the current schedule is not appropriate:
       ```
       aws kms update-key-rotation-period \
           --key-id <key-id> \
           --rotation-period-in-days <days>
       ```
  EOT

  opa_policy       = file("${path.module}/rego/aws_kms_key_rotation_warning.rego")
  scope_project_id = local.scope_project_id
}
