# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import the shared globals package which contains our trusted account lists.
import data.customPackage.jtb75globals as globals

# Default to "pass" so the rule only fails when conditions are met.
default result = "pass"

# Fail if the snapshot is shared publicly.
# When SharedAccounts contains "all", any AWS account can restore from this snapshot.
result = "fail" if {
    not is_null(input.SharedAccounts)
    some acct in input.SharedAccounts
    lower(acct) == "all"
}

# Fail if the snapshot is shared with an account not in either trusted list.
result = "fail" if {
    not is_null(input.SharedAccounts)
    some acct in input.SharedAccounts
    lower(acct) != "all"
    not acct in globals.trusted_internal_accounts
    not acct in globals.trusted_external_accounts
}

# Build a set of all untrusted account IDs found in SharedAccounts.
untrusted_accounts := {acct |
    not is_null(input.SharedAccounts)
    some acct in input.SharedAccounts
    lower(acct) != "all"
    not acct in globals.trusted_internal_accounts
    not acct in globals.trusted_external_accounts
}

# Helper rule that evaluates to true if the snapshot is publicly shared.
is_public if {
    not is_null(input.SharedAccounts)
    some acct in input.SharedAccounts
    lower(acct) == "all"
}

# Display the current state in Wiz findings.
currentConfiguration := concat(", ", array.concat(
    [msg | is_public; msg := "Snapshot is shared publicly"],
    [sprintf("Shared with untrusted account: %s", [acct]) | some acct in untrusted_accounts],
))

# Display the expected compliant state.
expectedConfiguration := "RDS snapshots should only be shared with accounts in the organization or trusted accounts list."
