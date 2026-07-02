"""
Remove untrusted principals from IAM role trust policies.

Pairs with CCR: JTB75 - IAM roles with untrusted account trust relationships

Compares each AWS principal in the role's AssumeRolePolicyDocument against
the trusted account lists. Removes statements with wildcard ("*") principals
and strips untrusted account ARNs from multi-principal statements.
Service principals (e.g. ec2.amazonaws.com) are always preserved.

The removed principals are saved as a tag (wiz:removed-principals) on the
role, enabling the revert function to re-add them to the trust policy.

IAM Permissions required (remediate):
- iam:GetRole
- iam:UpdateAssumeRolePolicy
- iam:TagRole

IAM Permissions required (revert):
- iam:GetRole
- iam:UpdateAssumeRolePolicy
- iam:UntagRole
"""

import json

import boto3
from botocore.exceptions import ClientError

from wiz.context import AwsRemediationContext
from wiz.models import TargetRemediationArgs
from wiz.logger import logger
from wiz.safe_remediate import remediate_and_log_error

TRUSTED_ACCOUNTS = {
    "123456789012",
    "234567890123",
    "345678901234",
    "494378024839",
}

BACKUP_TAG_KEY = "wiz:removed-principals"


def _extract_account_id(arn):
    """Extract the account ID from an IAM ARN."""
    parts = arn.split(":")
    if len(parts) >= 5:
        return parts[4]
    return None


def _is_trusted_principal(principal):
    """Check if an AWS principal is trusted (in the trusted accounts list)."""
    if principal == "*":
        return False
    account_id = _extract_account_id(principal)
    if account_id and account_id in TRUSTED_ACCOUNTS:
        return True
    return False


def _clean_trust_policy(policy):
    """Remove untrusted AWS principals from trust policy statements.

    Returns the cleaned policy and a list of removed principals.
    """
    cleaned_statements = []
    removed_principals = []

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            cleaned_statements.append(statement)
            continue

        principal = statement.get("Principal", {})

        # Handle Principal: "*" (any entity)
        if principal == "*":
            removed_principals.append("*")
            continue

        aws_principals = principal.get("AWS")
        if aws_principals is None:
            # No AWS principals (e.g. Service-only statement) — keep it
            cleaned_statements.append(statement)
            continue

        # Normalize to list
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]

        # Filter to only trusted principals
        trusted = [p for p in aws_principals if _is_trusted_principal(p)]
        untrusted = [p for p in aws_principals if not _is_trusted_principal(p)]
        removed_principals.extend(untrusted)

        if not trusted:
            # All AWS principals in this statement were untrusted — drop it
            # But preserve if there are also Service principals
            other_principals = {
                k: v for k, v in principal.items() if k != "AWS"
            }
            if other_principals:
                statement = dict(statement)
                statement["Principal"] = other_principals
                cleaned_statements.append(statement)
            continue

        # Rebuild the statement with only trusted principals
        statement = dict(statement)
        statement["Principal"] = dict(principal)
        statement["Principal"]["AWS"] = trusted[0] if len(trusted) == 1 else trusted
        cleaned_statements.append(statement)

    policy["Statement"] = cleaned_statements
    return policy, removed_principals


def remediate(context: AwsRemediationContext):
    remediation_args: TargetRemediationArgs = context.get_remediation_args()

    role_name = remediation_args.name
    region = remediation_args.region

    logger.info("Starting untrusted trust removal", role=role_name, region=region)

    session: boto3.Session = context.get_session()
    iam = session.client("iam", region_name=region)

    # Get the current trust policy
    try:
        response = iam.get_role(RoleName=role_name)
        trust_policy = response["Role"]["AssumeRolePolicyDocument"]
    except ClientError as e:
        error_msg = e.response["Error"]["Message"]
        logger.error("Failed to get role", role=role_name, error=error_msg)
        raise Exception(error_msg)

    # Clean the trust policy
    cleaned_policy, removed = _clean_trust_policy(trust_policy)

    if not removed:
        raise Exception(
            f"Role {role_name} has no untrusted principals to remove. "
            "A scan may not have run yet to close the finding."
        )

    logger.info(
        "Removing untrusted principals",
        role=role_name,
        removed=removed,
    )

    if not cleaned_policy.get("Statement"):
        raise Exception(
            f"Role {role_name} would have an empty trust policy after cleanup. "
            "Manual review required."
        )

    # Save removed principals as a tag for revert (comma-separated)
    removed_value = ",".join(removed)
    if len(removed_value) > 256:
        logger.warning(
            "Removed principals list too large for tag, revert will not be available",
            role=role_name,
            length=len(removed_value),
        )
    else:
        try:
            iam.tag_role(
                RoleName=role_name,
                Tags=[{"Key": BACKUP_TAG_KEY, "Value": removed_value}],
            )
            logger.info("Saved removed principals to tag", role=role_name, removed=removed_value)
        except ClientError as e:
            error_msg = e.response["Error"]["Message"]
            logger.warning("Failed to save backup tag", role=role_name, error=error_msg)

    # Update the trust policy
    try:
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(cleaned_policy),
        )
    except ClientError as e:
        error_msg = e.response["Error"]["Message"]
        logger.error("Failed to update trust policy", role=role_name, error=error_msg)
        raise Exception(error_msg)

    logger.info(
        "Successfully cleaned trust policy",
        role=role_name,
        removed_principals=removed,
    )


def revert(context: AwsRemediationContext):
    remediation_args: TargetRemediationArgs = context.get_remediation_args()

    role_name = remediation_args.name
    region = remediation_args.region

    logger.info("Starting trust policy revert", role=role_name, region=region)

    session: boto3.Session = context.get_session()
    iam = session.client("iam", region_name=region)

    # Get the backup tag
    try:
        response = iam.get_role(RoleName=role_name)
        existing_tags = {t["Key"]: t["Value"] for t in response["Role"].get("Tags", [])}
    except ClientError as e:
        error_msg = e.response["Error"]["Message"]
        logger.error("Failed to get role", role=role_name, error=error_msg)
        raise Exception(error_msg)

    removed_value = existing_tags.get(BACKUP_TAG_KEY)
    if not removed_value:
        raise Exception(
            f"Role {role_name} has no removed principals tag ({BACKUP_TAG_KEY}). "
            "Cannot revert."
        )

    removed_principals = removed_value.split(",")
    logger.info("Re-adding removed principals", role=role_name, principals=removed_principals)

    # Get the current trust policy to add principals back
    trust_policy = response["Role"]["AssumeRolePolicyDocument"]

    # Re-add each removed principal as a new Allow/AssumeRole statement
    for principal in removed_principals:
        if principal == "*":
            statement = {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        else:
            statement = {
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": "sts:AssumeRole",
            }
        trust_policy.setdefault("Statement", []).append(statement)

    try:
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy),
        )
    except ClientError as e:
        error_msg = e.response["Error"]["Message"]
        logger.error("Failed to restore trust policy", role=role_name, error=error_msg)
        raise Exception(error_msg)

    # Remove the backup tag
    try:
        iam.untag_role(RoleName=role_name, TagKeys=[BACKUP_TAG_KEY])
    except ClientError as e:
        logger.warning(
            "Failed to remove backup tag",
            role=role_name,
            error=e.response["Error"]["Message"],
        )

    logger.info("Successfully reverted trust policy", role=role_name)


if __name__ == "__main__":
    remediate_and_log_error(remediate)
