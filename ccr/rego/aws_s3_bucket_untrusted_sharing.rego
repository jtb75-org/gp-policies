# All Wiz custom rules must use the "wiz" package
package wiz

# Enable Rego v1 syntax (uses "if" and "in" keywords)
import rego.v1

# Import the shared globals package which contains our trusted account lists.
import data.customPackage.jtb75globals as globals

# The "result" variable controls the rule outcome.
# It must return "pass", "fail", or "skip".
# We default to "pass" so the rule only fails when our conditions are met.
default result = "pass"

# ---------------------------------------------------------------------------
# Helper: get the bucket's owning account ID from WizMetadata.
# This is used to ignore "self" references in policies — a bucket granting
# access to its own account is not a cross-account sharing concern.
# ---------------------------------------------------------------------------
owner_account := input.WizMetadata.accountId

# ---------------------------------------------------------------------------
# Helper: extract account ID from an ARN string.
# AWS ARNs follow the format: arn:aws:iam::<account_id>:<resource>
# We split on ":" and take the 5th element (0-indexed: 4).
# ---------------------------------------------------------------------------
extract_account(arn) := account_id if {
    parts := split(arn, ":")
    count(parts) >= 5
    account_id := parts[4]
    account_id != ""
}

# ---------------------------------------------------------------------------
# Helper: check if an account ID is trusted.
# Returns true if the account is the bucket owner, or in either trusted list.
# ---------------------------------------------------------------------------
is_trusted(account_id) if {
    account_id == owner_account
}

is_trusted(account_id) if {
    account_id in globals.trusted_internal_accounts
}

is_trusted(account_id) if {
    account_id in globals.trusted_external_accounts
}

# ---------------------------------------------------------------------------
# BUCKET POLICY CHECKS
# The bucketPolicy field is a JSON string, so we parse it with json.unmarshal().
# We then iterate over each Statement's Principal to find cross-account access.
# ---------------------------------------------------------------------------

# Parse the bucket policy JSON string into an object.
# If bucketPolicy is null or empty, parsed_policy will be undefined
# and the policy checks below will simply not trigger.
parsed_policy := json.unmarshal(input.bucketPolicy)

# Collect untrusted account IDs found in bucket policy principals.
# Principal.AWS can be either a single string or an array of strings.
# We handle both cases with separate comprehensions and union them together.

# Case 1: Principal.AWS is a single ARN string
policy_untrusted_accounts contains account_id if {
    some stmt in parsed_policy.Statement
    stmt.Effect == "Allow"
    arn := stmt.Principal.AWS
    is_string(arn)
    account_id := extract_account(arn)
    not is_trusted(account_id)
}

# Case 2: Principal.AWS is an array of ARN strings
policy_untrusted_accounts contains account_id if {
    some stmt in parsed_policy.Statement
    stmt.Effect == "Allow"
    is_array(stmt.Principal.AWS)
    some arn in stmt.Principal.AWS
    account_id := extract_account(arn)
    not is_trusted(account_id)
}

# Check for wildcard principal ("*") which grants public access.
# This can appear as Principal: "*" or Principal: { AWS: "*" }
policy_is_public if {
    some stmt in parsed_policy.Statement
    stmt.Effect == "Allow"
    stmt.Principal == "*"
}

policy_is_public if {
    some stmt in parsed_policy.Statement
    stmt.Effect == "Allow"
    stmt.Principal.AWS == "*"
}

# ---------------------------------------------------------------------------
# ACL CHECKS
# The bucketAcl.Grants array contains entries that can grant access via:
#   - URI: public access groups (e.g., AllUsers, AuthenticatedUsers)
#   - ID: canonical user IDs (cross-account sharing)
# We flag any grant with a public URI.
# Note: Canonical user ID-based cross-account grants are harder to map to
# account IDs, so we focus on public access detection in ACLs.
# ---------------------------------------------------------------------------

# URIs that indicate public or overly broad access
public_acl_uris := {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

acl_is_public if {
    some grant in input.bucketAcl.Grants
    grant.Grantee.URI in public_acl_uris
}

# ---------------------------------------------------------------------------
# INVENTORY CONFIGURATION CHECKS
# Inventory configurations can export bucket metadata to another account's
# S3 bucket. We check if the destinationAccountID is untrusted.
# ---------------------------------------------------------------------------
inventory_untrusted_accounts contains account_id if {
    some config in input.inventoryConfigurations
    account_id := config.destinationAccountID
    not is_trusted(account_id)
}

# ---------------------------------------------------------------------------
# RESULT EVALUATION
# The rule fails if ANY of the following are true:
#   - Bucket policy grants access to an untrusted account
#   - Bucket policy or ACL allows public access
#   - Inventory is configured to send data to an untrusted account
# ---------------------------------------------------------------------------
result = "fail" if {
    count(policy_untrusted_accounts) > 0
}

result = "fail" if {
    policy_is_public
}

result = "fail" if {
    acl_is_public
}

result = "fail" if {
    count(inventory_untrusted_accounts) > 0
}

# ---------------------------------------------------------------------------
# FINDINGS OUTPUT
# Build a human-readable summary of what was found for the Wiz finding.
# ---------------------------------------------------------------------------

# Collect all finding messages into a set, then join them.
finding_messages contains "Bucket policy allows public access" if {
    policy_is_public
}

finding_messages contains msg if {
    some acct in policy_untrusted_accounts
    msg := sprintf("Bucket policy grants access to untrusted account: %s", [acct])
}

finding_messages contains "Bucket ACL allows public access" if {
    acl_is_public
}

finding_messages contains msg if {
    some acct in inventory_untrusted_accounts
    msg := sprintf("Inventory configured to send to untrusted account: %s", [acct])
}

# "currentConfiguration" is displayed in Wiz findings to show
# the actual state of the resource that was evaluated.
currentConfiguration := concat(", ", finding_messages)

# "expectedConfiguration" is displayed in Wiz findings to describe
# what the compliant state should look like.
expectedConfiguration := "S3 buckets should only be shared with accounts in the organization or trusted accounts list."
