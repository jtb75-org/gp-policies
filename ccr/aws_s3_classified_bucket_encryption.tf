resource "wiz_cloud_configuration_rule" "aws_s3_classified_bucket_encryption" {
  name                     = "${var.prefix} - Classified S3 buckets must be encrypted"
  description              = "Identifies S3 buckets tagged with data-classification of confidential or highly-confidential that are missing server-side encryption. Buckets without a classified tag are skipped."
  target_native_types      = ["bucket"]
  severity                 = "HIGH"
  enabled                  = true
  remediation_instructions = <<-EOT
    1. Sign in to the AWS Management Console and navigate to **S3**.
    2. Select the affected bucket.
    3. Go to the **Properties** tab.
    4. Under **Default encryption**, click **Edit**.
    5. Enable **Server-side encryption** with either:
       - **SSE-S3** (Amazon S3-managed keys), or
       - **SSE-KMS** (AWS KMS-managed keys) for stronger protection.
    6. Click **Save changes**.

    **Via CLI:**
    ```
    aws s3api put-bucket-encryption \
        --bucket <bucket-name> \
        --server-side-encryption-configuration '{
          "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
              "SSEAlgorithm": "aws:kms"
            }
          }]
        }'
    ```
  EOT

  opa_policy = file("${path.module}/rego/aws_s3_classified_bucket_encryption.rego")
}
