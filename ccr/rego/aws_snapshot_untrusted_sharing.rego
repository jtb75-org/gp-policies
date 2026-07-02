# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import the shared globals package which contains our trusted account lists.
# This is a custom Rego package managed via wiz_custom_rego_package in Terraform.
# "globals" is an alias so we can reference it as globals.trusted_internal_accounts, etc.
import data.customPackage.jtb75globals as globals

# The "result" variable controls the rule outcome.
# It must return "pass", "fail", or "skip".
# We default to "pass" so the rule only fails when our conditions are met.
default result = "pass"

# Fail if the snapshot is shared publicly.
# When a snapshot's CreateVolumePermissions contains Group == "all",
# it means any AWS account can create volumes from this snapshot.
# "some i" iterates over each entry in the CreateVolumePermissions array.
result = "fail" if {
    some i
    input.CreateVolumePermissions[i].Group == "all"
}

# Fail if the snapshot is shared with an account not in either trusted list.
# Each entry in CreateVolumePermissions with a "UserId" represents an
# AWS account that has been granted access to this snapshot.
# Both "not ... in" checks must be true (implicit AND) for the rule to fail,
# meaning the account is in NEITHER the internal NOR the external trusted list.
result = "fail" if {
    some i
    account_id := input.CreateVolumePermissions[i].UserId
    not account_id in globals.trusted_internal_accounts
    not account_id in globals.trusted_external_accounts
}

# Build a set of all untrusted account IDs found in the sharing permissions.
# This uses a set comprehension: { value | condition }
# It collects every UserId that is not in either trusted list.
# Used below in currentConfiguration to list the offending accounts.
untrusted_accounts := {account_id |
    some i
    account_id := input.CreateVolumePermissions[i].UserId
    not account_id in globals.trusted_internal_accounts
    not account_id in globals.trusted_external_accounts
}

# Helper rule that evaluates to true if the snapshot is publicly shared.
# Used below in currentConfiguration to include a public-sharing message.
is_public if {
    some i
    input.CreateVolumePermissions[i].Group == "all"
}

# "currentConfiguration" is displayed in Wiz findings to show
# the actual state of the resource that was evaluated.
# We build a comma-separated string that includes:
#   - A public sharing warning (if applicable)
#   - Each untrusted account ID found in the sharing permissions
# array.concat() merges two arrays, and concat() joins them with ", ".
currentConfiguration := concat(", ", array.concat(
    [msg | is_public; msg := "Snapshot is shared publicly"],
    [sprintf("Shared with untrusted account: %s", [acct]) | some acct in untrusted_accounts],
))

# "expectedConfiguration" is displayed in Wiz findings to describe
# what the compliant state should look like.
expectedConfiguration := "EC2 snapshots should only be shared with accounts in the organization or trusted accounts list."
