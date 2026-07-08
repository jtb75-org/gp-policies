# =============================================================================
# Terraform — AWS Lambda S3 Malware Quarantine Architecture
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variable configuration
variable "prefix" {
  type        = string
  description = "Resource prefix for naming"
  default     = "jtb75"
}

variable "wiz_secret_name" {
  type        = string
  description = "AWS Secrets Manager secret name for Wiz API credentials"
  default     = "wiz-api-credentials"
}

variable "quarantine_bucket_name" {
  type        = string
  description = "Explicit quarantine bucket name (optional, if omitted will auto-locate)"
  default     = ""
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# 1. AWS SNS Topic for Wiz Workflow Alerts
resource "aws_sns_topic" "wiz_malware_alerts" {
  name = "${var.prefix}-wiz-malware-alerts"
  tags = {
    Project = "gp-policies-lambda-remediation"
  }
}

# SNS Topic Policy (allows local account publish and integrated Wiz role publish)
resource "aws_sns_topic_policy" "default" {
  arn    = aws_sns_topic.wiz_malware_alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    actions = ["sns:Publish"]
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = [aws_sns_topic.wiz_malware_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# 2. Archive Python Code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

# 3. AWS Lambda Function
resource "aws_lambda_function" "quarantine_s3_malware" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.prefix}-quarantine-s3-malware"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.12"
  timeout          = 180 # 3 minutes (matches our Python timeout configs)
  memory_size      = 256 # 256MB is plenty for processing metadata/EICAR downloads

  environment {
    variables = {
      WIZ_SECRET_NAME        = var.wiz_secret_name
      QUARANTINE_BUCKET_NAME = var.quarantine_bucket_name
    }
  }

  tags = {
    Project = "gp-policies-lambda-remediation"
  }
}

# 4. Lambda Trigger Permission (Allow SNS invocation)
resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.quarantine_s3_malware.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.wiz_malware_alerts.arn
}

# 5. SNS Subscription to Lambda
resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.wiz_malware_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.quarantine_s3_malware.arn
}

# 6. IAM Role for Lambda execution
resource "aws_iam_role" "lambda_exec" {
  name               = "${var.prefix}-quarantine-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Project = "gp-policies-lambda-remediation"
  }
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# IAM Execution Policy
resource "aws_iam_role_policy" "lambda_policy" {
  name   = "${var.prefix}-quarantine-lambda-policy"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

data "aws_iam_policy_document" "lambda_permissions" {
  # 1. CloudWatch Logging
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
  }

  # 2. AWS Secrets Manager access to fetch Wiz credentials
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect    = "Allow"
    resources = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.wiz_secret_name}-*"]
  }

  # 3. S3 Read/Write/Delete permissions for malware remediation
  statement {
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:ListBucket",
      "s3:ListBucketVersions"
    ]
    effect    = "Allow"
    resources = ["*"] # Required to locate and clean up any infected bucket in the account
  }
}

# Outputs for easier setup in Wiz
output "sns_topic_arn" {
  value       = aws_sns_topic.wiz_malware_alerts.arn
  description = "Provide this ARN to the Wiz SNS Integration settings"
}
