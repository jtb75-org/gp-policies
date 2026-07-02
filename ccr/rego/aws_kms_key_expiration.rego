# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import shared globals for thresholds
import data.customPackage.jtb75globals as globals

# Default to "pass" so the rule only fails when conditions are met.
default result = "pass"

# Convert threshold from days to nanoseconds.
warning_ns := globals.kms_expiration_warning_days * 24 * 60 * 60 * 1000000000

# Get the current time in nanoseconds.
now := time.now_ns()

# Skip keys that don't have an expiration date.
# Only imported key material (Origin: "EXTERNAL") has a ValidTo date.
result = "skip" if {
    is_null(input.ValidTo)
}

result = "skip" if {
    input.ValidTo == ""
}

# Skip keys that are not enabled.
result = "skip" if {
    input.KeyState != "Enabled"
}

# Fail if the key expires within the warning threshold.
result = "fail" if {
    input.KeyState == "Enabled"
    not is_null(input.ValidTo)
    input.ValidTo != ""
    expires := time.parse_rfc3339_ns(input.ValidTo)
    expires - now < warning_ns
}

# Calculate days until expiration for display.
days_until_expiration := round((time.parse_rfc3339_ns(input.ValidTo) - now) / (24 * 60 * 60 * 1000000000))

# Display the current state in Wiz findings.
currentConfiguration := sprintf("Origin: %s | KeyState: %s | ValidTo: %s | DaysUntilExpiration: %d", [
    input.Origin,
    input.KeyState,
    input.ValidTo,
    days_until_expiration,
])

# Display the expected compliant state.
expectedConfiguration := sprintf("Imported KMS key material should be renewed at least %d days before expiration.", [globals.kms_expiration_warning_days])
