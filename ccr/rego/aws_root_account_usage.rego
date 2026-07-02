# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import shared globals for thresholds
import data.customPackage.jtb75globals as globals

# Default to "pass" — the rule only fails when conditions are met.
default result = "pass"

# Convert thresholds from days to nanoseconds.
account_min_age_ns := globals.account_min_age_days * 24 * 60 * 60 * 1000000000
lookback_ns := globals.root_usage_lookback_days * 24 * 60 * 60 * 1000000000

# Get the current time in nanoseconds
now := time.now_ns()

# Determine when the account was created.
account_created := time.parse_rfc3339_ns(input.userCredentials.UserCreationTime)

# Skip accounts younger than the minimum age threshold.
# This gives the cloud platform team time to build the account with automation.
result = "skip" if {
    now - account_created < account_min_age_ns
}

# Check if the root password was used within the lookback window.
password_used_recently if {
    input.userCredentials.PasswordLastUsed != "N/A"
    last_used := time.parse_rfc3339_ns(input.userCredentials.PasswordLastUsed)
    now - last_used < lookback_ns
}

# Check if root access key 1 was used within the lookback window.
key1_used_recently if {
    input.userCredentials.AccessKey1LastUsedDate != "N/A"
    last_used := time.parse_rfc3339_ns(input.userCredentials.AccessKey1LastUsedDate)
    now - last_used < lookback_ns
}

# Check if root access key 2 was used within the lookback window.
key2_used_recently if {
    input.userCredentials.AccessKey2LastUsedDate != "N/A"
    last_used := time.parse_rfc3339_ns(input.userCredentials.AccessKey2LastUsedDate)
    now - last_used < lookback_ns
}

# Fail if the account is old enough AND root was used recently via any method.
result = "fail" if {
    now - account_created >= account_min_age_ns
    password_used_recently
}

result = "fail" if {
    now - account_created >= account_min_age_ns
    key1_used_recently
}

result = "fail" if {
    now - account_created >= account_min_age_ns
    key2_used_recently
}

# Calculate account age in whole days for display.
account_age_days := round((now - account_created) / (24 * 60 * 60 * 1000000000))

# Display the current state in Wiz findings.
currentConfiguration := sprintf("AccountAge: %dd | PasswordLastUsed: %s | AccessKey1LastUsed: %s | AccessKey2LastUsed: %s", [
    account_age_days,
    input.userCredentials.PasswordLastUsed,
    input.userCredentials.AccessKey1LastUsedDate,
    input.userCredentials.AccessKey2LastUsedDate,
])

# Display the expected compliant state.
expectedConfiguration := sprintf("Root account should not be used. Accounts younger than %d days are exempt.", [globals.account_min_age_days])
