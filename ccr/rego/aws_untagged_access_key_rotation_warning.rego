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

# The set of recognized values for the "type" tag.
# If a user has one of these, a more specific rule handles it.
recognized_types := {"user", "service", "vendor"}

# Helper: get the value of the "type" tag if it exists.
# Iterates over the Tags array looking for Key == "type".
# If no such tag exists, type_tag_value will be undefined.
type_tag_value := value if {
    some tag in input.Tags
    tag.Key == "type"
    value := tag.Value
}

# Helper: true if the user has a "type" tag with a recognized value.
# This means a more specific rule (user/service/vendor) will handle it.
has_recognized_type if {
    type_tag_value in recognized_types
}

# Skip this rule if the user has a recognized type tag.
# The user/service/vendor-specific rules will handle those cases.
result = "skip" if {
    has_recognized_type
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
    not has_recognized_type
    key1_stale
}

result = "fail" if {
    not has_recognized_type
    key2_stale
}

# Build a description of the tag state for the finding output.
tag_status := sprintf("type=%s (unrecognized)", [type_tag_value]) if {
    type_tag_value
    not type_tag_value in recognized_types
}

tag_status := "No type tag" if {
    not type_tag_value
}

# "currentConfiguration" is displayed in Wiz findings to show
# the actual state of the resource that was evaluated.
currentConfiguration := sprintf("%s | AccessKey1Active: %s, LastRotated: %s | AccessKey2Active: %s, LastRotated: %s", [
    tag_status,
    input.userCredentials.AccessKey1Active,
    input.userCredentials.AccessKey1LastRotated,
    input.userCredentials.AccessKey2Active,
    input.userCredentials.AccessKey2LastRotated,
])

# "expectedConfiguration" is displayed in Wiz findings to describe
# what the compliant state should look like.
expectedConfiguration := sprintf("All IAM users should have a valid type tag (user/service/vendor). Untagged access keys must be rotated at least every %d days.", [globals.user_key_warning_days])
