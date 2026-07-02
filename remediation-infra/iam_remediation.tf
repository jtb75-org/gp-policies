# =============================================================================
# IAM — Wiz remediation and response roles (official Wiz module)
# =============================================================================

module "remediation_roles" {
  source = "https://wizio-public.s3.amazonaws.com/deployment-v2/aws/wiz-aws-remediationandresponse-k8s-single-account-terraform-module.zip"

  cluster_arn      = aws_eks_cluster.remediation.arn
  namespace        = var.remediation_namespace
  resources_prefix = var.prefix

  permission_sets = {
    "rem-aws-ec2-response-001" : [
      "ec2:CreateTags",
      "ec2:DescribeInstances",
      "ec2:StopInstances",
      "tag:TagResources"
    ],
    "rem-aws-ec2-response-002" : [
      "ec2:CreateTags",
      "ec2:RebootInstances",
      "tag:TagResources"
    ],
    "rem-aws-ec2-response-003" : [
      "ec2:DescribeInstances",
      "ec2:TerminateInstances"
    ]
  }
}


