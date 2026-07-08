# Wiz S3 Malware Serverless Remediation Stack

This folder contains the serverless AWS Lambda and SNS infrastructure designed to auto-quarantine infected S3 files and post audit feedback comments back to your Wiz Portal.

---

## Architecture Overview

1. **Ingestion Topic:** An SNS topic (`jtb75-wiz-malware-alerts`) receives malware finding events pushed by Wiz.
2. **Lambda Processor:** Triggered by the SNS events, the Lambda:
   - Updates the target Wiz Issue status to `IN_PROGRESS`.
   - Safely relocates the malicious file version to an isolated quarantine S3 bucket.
   - Deletes the infected file version from the source S3 bucket.
   - Posts a detailed audit comment note back to the Wiz Issue drawer.
3. **Restore (Unquarantine) Action:** Supports moving files back from quarantine to their original source locations and cleaning up the quarantine copies.

---

## Deployment

### Prerequisites
1. **Wiz API Secret:** Ensure you have your Wiz Client ID and Client Secret stored in AWS Secrets Manager under the name `wiz-api-credentials` as a JSON block:
   ```json
   {
     "client_id": "YOUR_WIZ_CLIENT_ID",
     "client_secret": "YOUR_WIZ_CLIENT_SECRET"
   }
   ```
2. **Wiz Connector Permission:** The IAM Role assumed by the Wiz AWS connector integration (**`WizAccess-Role-Buhr`**) must have permissions to publish to the SNS topic:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "sns:Publish",
         "Resource": "arn:aws:sns:us-east-1:494378024839:jtb75-wiz-malware-alerts"
       }
     ]
   }
   ```

### Deploying the Stack
Run the following commands in this directory:
```bash
# Initialize Terraform
AWS_PROFILE=wiz-labs terraform init

# Deploy to AWS
AWS_PROFILE=wiz-labs terraform apply -auto-approve
```

---

## Wiz Integration Settings & Payloads

In the Wiz Portal, go to **Settings > Integrations > Add Integration > AWS SNS** and link it to the SNS topic ARN exported by Terraform:
`arn:aws:sns:us-east-1:494378024839:jtb75-wiz-malware-alerts`

Inside the integration, define two custom **Actions** using the JSON templates below:

### 1. Quarantine Action Payload
Configure this Action for your **Issue Created** (Malware detected) automation rule.

* **Directive:** `quarantine`
* **JSON Body:**
```json
{
  "directive": "quarantine",
  "issueId": "{{issue.id}}",
  "resourceId": "{{issue.entitySnapshot.providerId}}",
  "id": "{{issue.entitySnapshot.id}}"
}
```

### 2. Unquarantine (Restore) Action Payload
Configure this Action to run **manually** or on **status changes** to restore files back to their source.

* **Directive:** `unquarantine`
* **JSON Body:**
```json
{
  "directive": "unquarantine",
  "issueId": "{{issue.id}}",
  "resourceId": "{{issue.entitySnapshot.providerId}}",
  "id": "{{issue.entitySnapshot.id}}"
}
```

---

## Required Wiz API Scopes
Ensure that the Service Account client credentials configured in AWS Secrets Manager have the following scopes in the Wiz Portal:
- `write:issue_comments` (to write audit notes back)
- `write:issue_status` (to move the issue to `In Progress`)
- `read:issues` (required by GraphQL auth validation when modifying issue properties)
- `read:controls` & `read:resources` (for S3 bucket-level fallback Graph searches)
