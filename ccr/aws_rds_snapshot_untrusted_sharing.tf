resource "wiz_cloud_configuration_rule" "aws_rds_snapshot_untrusted_sharing" {
  name                     = "${var.prefix} - RDS snapshots shared with untrusted accounts"
  description              = "Identifies RDS database snapshots shared publicly or with AWS accounts not in the organization or trusted accounts list."
  target_native_types      = ["rds#snapshot", "rds#clustersnapshot"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **RDS > Snapshots**.
    2. Select the affected snapshot.
    3. Choose **Actions > Share snapshot**.
    4. Remove any untrusted account IDs from the shared accounts list.
    5. If the snapshot is public, change **DB snapshot visibility** to **Private**.

    **Via CLI (DB Instance Snapshot):**
    ```
    aws rds modify-db-snapshot-attribute \
        --db-snapshot-identifier <snapshot-id> \
        --attribute-name restore \
        --values-to-remove 'all'
    ```

    **Via CLI (DB Cluster Snapshot):**
    ```
    aws rds modify-db-cluster-snapshot-attribute \
        --db-cluster-snapshot-identifier <snapshot-id> \
        --attribute-name restore \
        --values-to-remove 'all'
    ```
  EOT

  opa_policy = file("${path.module}/rego/aws_rds_snapshot_untrusted_sharing.rego")
}
