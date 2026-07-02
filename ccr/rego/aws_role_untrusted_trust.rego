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
# ARN format: arn:aws:iam::ACCOUNT_ID:...
cross_account_ids := {account_id |
    some statement in trust_policy.Statement
    statement.Effect == "Allow"
    aws_principals := statement.Principal.AWS
    principal := aws_principals[_]
    principal != "*"
    parts := split(principal, ":")
    account_id := parts[4]
}

# Also handle Principal.AWS as a single string (not array).
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

# Check if any statement trusts all AWS accounts ("*").
is_public if {
    some statement in trust_policy.Statement
    statement.Effect == "Allow"
    statement.Principal.AWS == "*"
}

is_public if {
    some statement in trust_policy.Statement
    statement.Effect == "Allow"
    statement.Principal == "*"
}

is_public if {
    some statement in trust_policy.Statement
    statement.Effect == "Allow"
    some principal in statement.Principal.AWS
    principal == "*"
}

# Skip if there are no cross-account AWS principals and not public.
# This means the role only trusts AWS services or federated providers.
result = "skip" if {
    not is_public
    count(all_cross_account_ids) == 0
}

# Fail if the role trusts all AWS accounts.
result = "fail" if {
    not is_skip
    is_public
}

# Fail if any trusted account is not in the trusted lists.
result = "fail" if {
    not is_skip
    some account_id in all_cross_account_ids
    not account_id in globals.trusted_internal_accounts
    not account_id in globals.trusted_external_accounts
}

# Helper to prevent Rego conflict between skip and fail.
is_skip if {
    not is_public
    count(all_cross_account_ids) == 0
}

# Build set of untrusted account IDs for evidence.
untrusted_accounts := {account_id |
    some account_id in all_cross_account_ids
    not account_id in globals.trusted_internal_accounts
    not account_id in globals.trusted_external_accounts
}

# Display the current state in Wiz findings.
currentConfiguration := concat(", ", array.concat(
    [msg | is_public; msg := "Role trust policy allows any AWS account"],
    [sprintf("Trusted by untrusted account: %s", [acct]) | some acct in untrusted_accounts],
))

# Display the expected compliant state.
expectedConfiguration := "IAM roles should only trust accounts in the organization or trusted accounts list."
