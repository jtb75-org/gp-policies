# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import shared globals for rotation thresholds
import data.customPackage.jtb75globals as globals

# The "result" variable controls the rule outcome.
# It must return "pass", "fail", or "skip".
# We default to "pass" so the rule only fails when our conditions are met.
default result = "pass"

# Convert the warning threshold from days to nanoseconds.
# This is an early-warning rule that fires before the hard limit.
threshold_ns := globals.user_key_warning_days * 24 * 60 * 60 * 1000000000

# Get the current time in nanoseconds
now := time.now_ns()

# Helper: check if the IAM user has a tag with Key="type" and Value="user".
# The Tags array contains objects with "Key" and "Value" fields.
# "some tag in input.Tags" iterates over each tag entry.
is_user if {
    some tag in input.Tags
    tag.Key == "type"
    tag.Value == "user"
}

# Skip this rule if the IAM user is not tagged as a human user.
# Returning "skip" means Wiz will not evaluate or report on this resource.
result = "skip" if {
    not is_user
}

# Check if Access Key 1 is active.
# The value comes from the AWS credential report as a string ("true"/"false").
key1_active := input.userCredentials.AccessKey1Active == "true"

# Determine if Access Key 1 is stale (older than warning threshold).
# This rule is true only when BOTH conditions inside are true (implicit AND):
#   1. The key is active
#   2. The time since last rotation exceeds the warning threshold
key1_stale if {
    key1_active
    rotated := time.parse_rfc3339_ns(input.userCredentials.AccessKey1LastRotated)
    now - rotated > threshold_ns
}

# Same checks for Access Key 2
key2_active := input.userCredentials.AccessKey2Active == "true"

key2_stale if {
    key2_active
    rotated := time.parse_rfc3339_ns(input.userCredentials.AccessKey2LastRotated)
    now - rotated > threshold_ns
}

# Set result to "fail" if either key is stale.
# In Rego, multiple rules with the same name act as OR logic.
result = "fail" if {
    is_user
    key1_stale
}

result = "fail" if {
    is_user
    key2_stale
}

# "currentConfiguration" is displayed in Wiz findings to show
# the actual state of the resource that was evaluated.
currentConfiguration := sprintf("Type: user | AccessKey1Active: %s, LastRotated: %s | AccessKey2Active: %s, LastRotated: %s", [
    input.userCredentials.AccessKey1Active,
    input.userCredentials.AccessKey1LastRotated,
    input.userCredentials.AccessKey2Active,
    input.userCredentials.AccessKey2LastRotated,
])

# "expectedConfiguration" is displayed in Wiz findings to describe
# what the compliant state should look like.
expectedConfiguration := sprintf("User access keys should be rotated at least every %d days.", [globals.user_key_warning_days])
