# GP Policies - Wiz Cloud Security Management

This repository manages Wiz Cloud Configuration Rules (CCRs), remediation actions, and supporting test infrastructure. All Wiz resources are prefixed with `JTB75` for identification within the Wiz portal.

## Repository Structure

```
gp-policies/
├── ccr/                          # Wiz CCR rules (Wiz Terraform provider)
│   ├── provider.tf               # Wiz Terraform provider configuration
│   ├── rego_packages.tf          # Custom Rego package definitions
│   ├── aws_*.tf                  # Terraform resource definitions for each CCR
│   ├── rego/
│   │   ├── packages/
│   │   │   └── jtb75_globals.rego  # Shared variables (account lists, thresholds, role names)
│   │   └── aws_*.rego            # Rego policy files for each CCR
│   └── tests/
│       ├── test_ccr.py           # Test a single rule against a fixture or live resources
│       ├── validate_fixtures.py  # Run all fixtures against their rules (full test suite)
│       ├── fetch_fixtures.py     # Fetch real resource JSONs from Wiz Graph API
│       └── fixtures/             # Mock resource JSON files for controlled testing
├── remediation-infra/            # EKS cluster for Wiz Outpost Lite (AWS Terraform provider)
│   ├── vpc.tf                    # Dedicated VPC with public/private subnets
│   ├── eks.tf                    # EKS cluster, node group, Pod Identity Agent
│   ├── iam_remediation.tf        # Runner and worker IAM roles
│   └── kubernetes.tf             # Namespace and service account
├── test-infra/                   # Disposable AWS resources to trigger CCRs (AWS Terraform provider)
│   ├── iam_roles.tf              # Roles with missing tags, untrusted trusts
│   ├── iam_users.tf              # Users with managed policies, access keys
│   ├── s3.tf                     # Buckets with untrusted sharing, missing encryption
│   ├── snapshots.tf              # EC2 snapshots shared with untrusted accounts
│   ├── rds.tf                    # RDS instances with low backup retention
│   └── api_gateway.tf            # API Gateway methods without authorization
├── docs/
│   ├── creating-rules.md         # Step-by-step guide for new CCRs
│   └── rego-reference.md         # Rego language reference for Wiz CCRs
├── RULES.md                      # Complete rules reference with fixtures
├── .env                          # Credentials (gitignored)
└── .gitignore
```

Each top-level directory (`ccr/`, `remediation-infra/`, `test-infra/`) is an independent Terraform root with its own provider, state, and `terraform apply`.

## Current Rules

This repository manages 32 CCRs across nine categories:

- **Access Key Rotation** — 8 rules enforcing key age limits by account type (service/vendor/user/untagged), each with a hard limit and early warning
- **Tag Enforcement** — 10 rules requiring valid `type` tags on IAM users, specific role lists, consumer roles, deploy roles, support-saml roles, the Administrator role, service/service-linked roles, and roles with external trust relationships
- **Untrusted Account Sharing** — 5 rules detecting EC2 snapshots, AMIs, RDS snapshots, S3 buckets, and IAM role trusts shared with accounts outside trusted lists
- **Root Account Usage** — 3 rules alerting on root account activity, programmatic access keys, and missing MFA
- **Data Protection** — 1 rule requiring encryption on S3 buckets tagged as confidential or highly-confidential
- **Database Configuration** — 1 rule enforcing minimum 35-day backup retention on RDS instances
- **KMS Key Management** — 2 rules warning on imported key material expiration and upcoming key rotation
- **IAM Policy Hygiene** — 1 rule detecting IAM users with AWS managed policies attached
- **API Gateway Security** — 1 rule detecting API Gateway methods without authorization, with exemption for `authentication:kochid` tagged APIs

See [RULES.md](RULES.md) for the complete rules reference, including descriptions, globals dependencies, and test fixtures for each rule.

## Setup

### Prerequisites

- Terraform 0.14+
- A Wiz service account with Custom Integration (GraphQL API) type and write permissions
- AWS credentials (with permissions to create IAM roles, OIDC providers, S3, DynamoDB, EKS, and VPC)
- GitHub CLI (`gh`) authenticated to your repository (for secrets configuration)

### 1. Local Authentication (for Bootstrap & CLI)

Create a `.env` file in the root of the repository (this file is gitignored):

```bash
# Wiz credentials (for ccr/)
export WIZ_CLIENT_ID=your-client-id
export WIZ_CLIENT_SECRET=your-client-secret

# AWS credentials (for bootstrap and local administration)
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

### 2. Bootstrap Terraform Backend

Before running any Terraform, you must create the S3 bucket and DynamoDB table used for storing the remote state. Run the following commands locally using your configured AWS credentials (e.g. using the `wiz-labs` profile):

```bash
# Get your AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="jtb75-terraform-state-${ACCOUNT_ID}"

# Create S3 Bucket for State
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration '{"BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true}'

# Create DynamoDB Table for Locks
aws dynamodb create-table \
  --table-name jtb75-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

### 3. Configure GitHub OIDC Trust

To allow GitHub Actions to deploy resources without storing permanent AWS credentials, configure an OIDC trust between GitHub and AWS:

1.  **Create the OIDC Provider in AWS** (if it doesn't exist):
    ```bash
    aws iam create-open-id-connect-provider \
      --url "https://token.actions.githubusercontent.com" \
      --client-id-list "sts.amazonaws.com" \
      --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1"
    ```
2.  **Create the IAM Role for GitHub Actions** with a trust policy allowing access from your repository (`jtb75-org/gp-policies`).
3.  **Attach permissions** (e.g., `AdministratorAccess` for lab environments) to the role.
4.  **Set the GitHub Secret** `AWS_ROLE_ARN` with the ARN of the created role:
    ```bash
    gh secret set AWS_ROLE_ARN -b "arn:aws:iam::YOUR_ACCOUNT_ID:role/github-actions-remediation-role"
    ```

### 4. Configure GitHub Secrets

Configure the following secrets in your GitHub repository for the workflows to run:

| Secret | Description | Source |
| :--- | :--- | :--- |
| `AWS_ROLE_ARN` | IAM Role for GitHub Actions (OIDC) | Created in Step 3 |
| `WIZ_CLIENT_ID` | Wiz API Client ID | Your Wiz Service Account (e.g. from `.env`) |
| `WIZ_CLIENT_SECRET` | Wiz API Client Secret | Your Wiz Service Account (e.g. from `.env`) |
| `WIZ_DOCKER_USERNAME` | Wiz Container Registry Username | Wiz Portal (Tenant Info) |
| `WIZ_DOCKER_PASSWORD` | Wiz Container Registry Password | Wiz Portal (Tenant Info) |

### 5. Deployment via GitHub Actions

The deployments are automated via GitHub Actions workflows:

*   **Remediation Infrastructure (EKS):** Triggered automatically on push to `main` when files in `remediation-infra/` change. Can also be run manually via the Actions tab.
*   **Wiz CCR Rules:** Triggered automatically on push to `main` when files in `ccr/` change.
*   **Outpost Lite (Helm):** Must be run **manually** via the Actions tab (`Outpost Lite - Wiz Helm Deployment`) once the EKS cluster and CCR deployments are complete.

---

### Alternative: Local Deployment

If you prefer to deploy manually from your local machine, you can run:

```bash
source .env

# Deploy CCR Rules
cd ccr
terraform init -backend-config="bucket=jtb75-terraform-state-YOUR_ACCOUNT_ID"
terraform apply

# Deploy Remediation Infra
cd remediation-infra
terraform init -backend-config="bucket=jtb75-terraform-state-YOUR_ACCOUNT_ID"
terraform apply
```

## Testing Rules

All test commands should be run from the `ccr/` directory:

```bash
source .env
cd ccr

# Test a rule against a specific fixture
python tests/test_ccr.py rego/aws_support_role_missing_type_tag.rego role \
  --input tests/fixtures/role_support_no_type_tag.json

# Run the full test suite (111 fixture/rule combinations)
python tests/validate_fixtures.py

# Fetch real resource JSONs for fixtures
python tests/fetch_fixtures.py role --count 3

# Test against live resources
python tests/test_ccr.py rego/aws_missing_type_tag.rego user --first 500
```

**Note:** After deploying changes to the globals package via Terraform, allow up to 30 minutes for Wiz to propagate the updates before testing against live resources. The JSON test mode (`--input`) is not affected by this delay.

## Adding a New Rule

See [docs/creating-rules.md](docs/creating-rules.md) for a step-by-step guide on creating new CCRs.
