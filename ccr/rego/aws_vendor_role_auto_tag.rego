# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import the shared globals package which contains our trusted account lists.
import data.customPackage.jtb75globals as globals

# Default to "pass" so the rule only fails when conditions are met.
default result = "pass"

# Parse the AssumeRolePolicyDocument JSON string into an object.
trust_policy := json.unmarshal(input.AssumeRolePolicyDocument)

# Collect all AWS account IDs from trust policy principals.
# Principal.AWS can be a single string or an array of strings.
cross_account_ids := {account_id |
    some statement in trust_policy.Statement
    statement.Effect == "Allow"
    aws_principals := statement.Principal.AWS
    principal := aws_principals[_]
    principal != "*"
    parts := split(principal, ":")
    account_id := parts[4]
}

# Handle Principal.AWS as a single string (not array).
cross_account_ids_single := {account_id |
    some statement in trust_policy.Statement
    statement.Effect == "Allow"
    principal := statement.Principal.AWS
    is_string(principal)
    principal != "*"
    parts := split(principal, ":")
    account_id := parts[4]
}

# Union of both extraction methods.
all_cross_account_ids := cross_account_ids | cross_account_ids_single

# Find which trusted external accounts this role trusts.
trusted_external_matches := {account_id |
    some account_id in all_cross_account_ids
    account_id in globals.trusted_external_accounts
}

# Check if the role has a type:vendor tag.
has_vendor_tag if {
    some tag in input.Tags
    lower(tag.Key) == "type"
    lower(tag.Value) == "vendor"
}

# Skip if the role does not trust any external trusted accounts.
# This is not a vendor role (no external trust relationship).
is_skip if {
    count(trusted_external_matches) == 0
}

result = "skip" if {
    is_skip
}

# Fail if the role trusts an external trusted account but lacks type:vendor tag.
result = "fail" if {
    not is_skip
    not has_vendor_tag
}

# Display the current state in Wiz findings.
currentConfiguration := sprintf("Role trusts external accounts [%s] but is missing type:vendor tag", [
    concat(", ", trusted_external_matches),
])

# Display the expected compliant state.
expectedConfiguration := "Roles with trust relationships to external trusted accounts should be tagged type:vendor."
