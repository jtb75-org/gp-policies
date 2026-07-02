# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import shared globals for thresholds
import data.customPackage.jtb75globals as globals

# Default to "pass" so the rule only fails when conditions are met.
default result = "pass"

# Helper: true if this instance is a read replica.
is_read_replica if {
    input.ReadReplicaSourceDBInstanceIdentifier
    not is_null(input.ReadReplicaSourceDBInstanceIdentifier)
}

# Skip read replicas — they inherit backup settings from the primary.
result = "skip" if {
    is_read_replica
}

# Fail if the backup retention period is below the required threshold.
# Excludes read replicas to avoid conflicting with the skip rule.
result = "fail" if {
    not is_read_replica
    input.BackupRetentionPeriod < globals.rds_backup_retention_days
}

# Display the current state in Wiz findings.
currentConfiguration := sprintf("BackupRetentionPeriod: %d days", [input.BackupRetentionPeriod])

# Display the expected compliant state.
expectedConfiguration := sprintf("BackupRetentionPeriod should be at least %d days per GP DBA team standards.", [globals.rds_backup_retention_days])
