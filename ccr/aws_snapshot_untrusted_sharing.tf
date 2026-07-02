resource "wiz_cloud_configuration_rule" "aws_snapshot_untrusted_sharing" {
  name                     = "${var.prefix} - EC2 snapshots shared with untrusted accounts"
  description              = "Identifies EC2 snapshots shared with AWS accounts not in the organization or trusted accounts list."
  target_native_types      = ["ec2#encryptedsnapshot", "ec2#unencryptedsnapshot"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **EC2 > Snapshots**.
    2. Select the affected snapshot.
    3. Choose **Actions > Modify permissions**.
    4. Remove any untrusted account IDs from the shared accounts list.
    5. If the snapshot is public, change it to **Private**.
  EOT

  opa_policy = file("${path.module}/rego/aws_snapshot_untrusted_sharing.rego")
}
