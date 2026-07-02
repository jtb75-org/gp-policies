# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import shared globals for thresholds
import data.customPackage.jtb75globals as globals

# Default to "pass" so the rule only fails when conditions are met.
default result = "pass"

# Convert threshold from days to nanoseconds.
warning_ns := globals.kms_rotation_warning_days * 24 * 60 * 60 * 1000000000

# Get the current time in nanoseconds.
now := time.now_ns()

# Skip keys without rotation enabled.
result = "skip" if {
    not input.keyRotationStatus
}

result = "skip" if {
    input.keyRotationStatus.KeyRotationEnabled == false
}

# Skip keys without a NextRotationDate.
result = "skip" if {
    input.keyRotationStatus.KeyRotationEnabled == true
    is_null(input.keyRotationStatus.NextRotationDate)
}

# Fail if the next rotation is within the warning threshold.
result = "fail" if {
    input.keyRotationStatus.KeyRotationEnabled == true
    not is_null(input.keyRotationStatus.NextRotationDate)
    rotation_date := time.parse_rfc3339_ns(input.keyRotationStatus.NextRotationDate)
    rotation_date - now < warning_ns
}

# Calculate days until rotation for display.
days_until_rotation := round((time.parse_rfc3339_ns(input.keyRotationStatus.NextRotationDate) - now) / (24 * 60 * 60 * 1000000000))

# Display the current state in Wiz findings.
currentConfiguration := sprintf("KeyRotationEnabled: %v | NextRotationDate: %s | DaysUntilRotation: %d", [
    input.keyRotationStatus.KeyRotationEnabled,
    input.keyRotationStatus.NextRotationDate,
    days_until_rotation,
])

# Display the expected compliant state.
expectedConfiguration := sprintf("KMS key rotation should be addressed at least %d days before the scheduled date.", [globals.kms_rotation_warning_days])
