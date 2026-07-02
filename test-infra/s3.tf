# =============================================================================
# S3 Buckets — Test fixtures for untrusted sharing and encryption CCRs
# =============================================================================

# Triggers: aws_s3_bucket_untrusted_sharing (bucket policy grants access to untrusted account)
resource "aws_s3_bucket" "test_untrusted_sharing" {
  bucket        = "${var.prefix}-test-untrusted-sharing-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Purpose = "test-ccr"
  }
}

resource "aws_s3_bucket_public_access_block" "test_untrusted_sharing" {
  bucket                  = aws_s3_bucket.test_untrusted_sharing.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "test_untrusted_sharing" {
  bucket = aws_s3_bucket.test_untrusted_sharing.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowUntrustedAccount"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.test_untrusted_sharing.arn}/*"
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.test_untrusted_sharing]
}

# Triggers: aws_s3_classified_bucket_encryption (classified bucket without encryption)
resource "aws_s3_bucket" "test_classified_no_encryption" {
  bucket        = "${var.prefix}-test-classified-noenc-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Purpose             = "test-ccr"
    data-classification = "confidential"
  }
}

# PASS: classified bucket WITH encryption
resource "aws_s3_bucket" "test_classified_encrypted" {
  bucket        = "${var.prefix}-test-classified-enc-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Purpose             = "test-ccr"
    data-classification = "confidential"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_classified_encrypted" {
  bucket = aws_s3_bucket.test_classified_encrypted.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# PASS: bucket with policy sharing to trusted internal account only
resource "aws_s3_bucket" "test_trusted_sharing" {
  bucket        = "${var.prefix}-test-trusted-sharing-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Purpose = "test-ccr"
  }
}

resource "aws_s3_bucket_policy" "test_trusted_sharing" {
  bucket = aws_s3_bucket.test_trusted_sharing.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowTrustedAccount"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.test_trusted_sharing.arn}/*"
      }
    ]
  })
}

# --- Malware Testing ---
resource "aws_s3_bucket" "test_malware" {
  bucket        = "${var.prefix}-test-malware-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Purpose = "test-malware"
  }
}

resource "aws_s3_bucket_versioning" "test_malware" {
  bucket = aws_s3_bucket.test_malware.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "malware_file_1" {
  bucket  = aws_s3_bucket.test_malware.id
  key     = "eicar_test_1.txt"
  content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
}

resource "aws_s3_object" "malware_file_2" {
  bucket  = aws_s3_bucket.test_malware.id
  key     = "eicar_test_2.txt"
  content = "Some other dummy malware content 2"
}

resource "aws_s3_object" "malware_file_3" {
  bucket  = aws_s3_bucket.test_malware.id
  key     = "eicar_test_3.txt"
  content = "Some other dummy malware content 3"
}
