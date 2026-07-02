# =============================================================================
# S3 Bucket — Quarantine storage for malicious files
# =============================================================================

resource "aws_s3_bucket" "quarantine" {
  bucket        = "${var.prefix}-wiz-quarantine-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # Safe for development; in production, you might want to prevent accidental deletion.
  tags = {
    Name        = "${var.prefix}-wiz-quarantine"
    Environment = "Security"
    Purpose     = "remediation-quarantine"
  }
}

# Block all public access to the quarantine bucket (Critical for security!)
resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket                  = aws_s3_bucket.quarantine.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Enable versioning on the quarantine bucket
resource "aws_s3_bucket_versioning" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  versioning_configuration {
    status = "Enabled"
  }
}
