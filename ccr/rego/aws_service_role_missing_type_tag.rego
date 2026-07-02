# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import the shared globals package which contains our service role names.
import data.customPackage.jtb75globals as globals

# The "result" variable controls the rule outcome.
# It must return "pass", "fail", or "skip".
# We default to "pass" so the rule only fails when our conditions are met.
default result = "pass"

# The set of recognized values for the "type" tag.
recognized_types := {"user", "service", "vendor"}

# Helper: check if this role's name matches one of the known service roles.
# globals.kbs_service_roles is a set of known service role name strings.
# input.RoleName is the IAM role name from the AWS resource JSON.
is_service_role if {
    input.RoleName in globals.kbs_service_roles
}

# Skip this rule if the role is not a known service role.
# We only care about enforcing type tags on service roles.
# Returning "skip" means Wiz will not evaluate or report on this resource.
result = "skip" if {
    not is_service_role
}

# Helper: get the value of the "type" tag if it exists.
# Iterates over the Tags array looking for Key == "type".
# If no such tag exists, type_tag_value will be undefined.
type_tag_value := value if {
    some tag in input.Tags
    tag.Key == "type"
    value := tag.Value
}

# Helper: true if the role has a "type" tag with a recognized value.
has_recognized_type if {
    type_tag_value in recognized_types
}

# Fail if the service role does not have a recognized type tag.
# This catches both missing tags and unrecognized values.
result = "fail" if {
    is_service_role
    not has_recognized_type
}

# Build a description of the tag state for the finding output.
# Shows either the unrecognized tag value or that no type tag exists.
tag_status := sprintf("type=%s (unrecognized)", [type_tag_value]) if {
    type_tag_value
    not type_tag_value in recognized_types
}

tag_status := "No type tag" if {
    not type_tag_value
}

# "currentConfiguration" is displayed in Wiz findings to show
# the actual state of the resource that was evaluated.
currentConfiguration := sprintf("Role: %s | %s", [input.RoleName, tag_status])

# "expectedConfiguration" is displayed in Wiz findings to describe
# what the compliant state should look like.
expectedConfiguration := "Service roles must have a type tag with a valid value: user, service, or vendor."
