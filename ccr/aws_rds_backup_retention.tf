resource "wiz_cloud_configuration_rule" "aws_rds_backup_retention" {
  name        = "${var.prefix} - RDS backup retention period should be at least 35 days"
  description = "Identifies RDS database instances with a backup retention period below 35 days. Read replicas are skipped. This threshold is based on GP DBA team best practices."
  target_native_types = [
    "rds/AmazonAuroraMySQL/instance",
    "rds/AmazonAuroraPostgreSQL/instance",
    "rds/AmazonDocDB/instance",
    "rds/MSSQLServer/instance",
    "rds/MySQL/instance",
    "rds/Cluster/MySQL/instance",
    "rds/AmazonNeptune/instance",
    "rds/Oracle/instance",
    "rds/PostgreSQL/instance",
    "rds/Cluster/PostgreSQL/instance",
    "rds/MariaDB/instance",
  ]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **RDS > Databases**.
    2. Select the affected DB instance.
    3. Choose **Modify**.
    4. Under **Backup**, set the **Backup retention period** to at least **35 days**.
    5. Choose **Continue** and apply the change.

    **Via CLI:**
    ```
    aws rds modify-db-instance \
        --db-instance-identifier <instance-id> \
        --backup-retention-period 35 \
        --apply-immediately
    ```
  EOT

  opa_policy       = file("${path.module}/rego/aws_rds_backup_retention.rego")
  scope_project_id = local.scope_project_id
  depends_on       = [wiz_custom_rego_package.jtb75_globals]
}
