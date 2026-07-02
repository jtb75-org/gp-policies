# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import shared globals for thresholds
import data.customPackage.jtb75globals as globals

# Default to "pass" — the rule only fails when conditions are met.
default result = "pass"

# Convert grace period from days to nanoseconds.
grace_period_ns := globals.root_mfa_grace_days * 24 * 60 * 60 * 1000000000

# Get the current time in nanoseconds.
now := time.now_ns()

# Determine when the account was created.
account_created := time.parse_rfc3339_ns(input.userCredentials.UserCreationTime)

# Calculate account age in whole days for display.
account_age_days := round((now - account_created) / (24 * 60 * 60 * 1000000000))

# Skip accounts younger than the grace period.
# Gives the cloud platform team time to complete account setup.
result = "skip" if {
    now - account_created < grace_period_ns
}

# Fail if MFA is not enabled on the root account.
# AccountMFAEnabled is 0 (disabled) or 1 (enabled).
result = "fail" if {
    now - account_created >= grace_period_ns
    input.AccountMFAEnabled != 1
}

# Display the current state in Wiz findings.
currentConfiguration := sprintf("AccountAge: %dd | MFA Enabled: %v", [account_age_days, input.AccountMFAEnabled])

# Display the expected compliant state.
expectedConfiguration := sprintf("Root accounts must have MFA enabled. Accounts younger than %d days are exempt.", [globals.root_mfa_grace_days])
