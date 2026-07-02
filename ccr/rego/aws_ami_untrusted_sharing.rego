# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import the shared globals package which contains our trusted account lists.
import data.customPackage.jtb75globals as globals

# Default to "pass" so the rule only fails when conditions are met.
default result = "pass"

# Fail if the AMI is shared publicly via LaunchPermissions.
result = "fail" if {
    some i
    input.LaunchPermissions[i].Group == "all"
}

# Fail if the AMI's Public flag is true (catches public AMIs even if
# LaunchPermissions is null due to how Wiz normalizes the data).
result = "fail" if {
    input.Public == true
}

# Fail if the AMI is shared with an account not in either trusted list.
result = "fail" if {
    some i
    account_id := input.LaunchPermissions[i].UserId
    not account_id in globals.trusted_internal_accounts
    not account_id in globals.trusted_external_accounts
}

# Build a set of all untrusted account IDs found in LaunchPermissions.
untrusted_accounts := {account_id |
    some i
    account_id := input.LaunchPermissions[i].UserId
    not account_id in globals.trusted_internal_accounts
    not account_id in globals.trusted_external_accounts
}

# Helper rule that evaluates to true if the AMI is publicly shared.
is_public if {
    some i
    input.LaunchPermissions[i].Group == "all"
}

is_public if {
    input.Public == true
}

# Display the current state in Wiz findings.
currentConfiguration := concat(", ", array.concat(
    [msg | is_public; msg := "AMI is shared publicly"],
    [sprintf("Shared with untrusted account: %s", [acct]) | some acct in untrusted_accounts],
))

# Display the expected compliant state.
expectedConfiguration := "EC2 AMIs should only be shared with accounts in the organization or trusted accounts list."
