variable "region" {
  description = "AWS region for the EKS cluster"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "joe-buhr-wiz-remediation"
}

variable "cluster_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.35"
}

variable "node_instance_type" {
  description = "EC2 instance type for EKS managed node group"
  type        = string
  default     = "t3.medium"
}

variable "node_desired_count" {
  description = "Desired number of nodes in the managed node group"
  type        = number
  default     = 2
}

variable "node_min_count" {
  description = "Minimum number of nodes"
  type        = number
  default     = 1
}

variable "node_max_count" {
  description = "Maximum number of nodes"
  type        = number
  default     = 3
}

variable "remediation_namespace" {
  description = "Kubernetes namespace for Wiz remediation pods"
  type        = string
  default     = "wiz-remediation"
}


variable "cluster_admin_arns" {
  description = "List of IAM ARNs to grant cluster admin access"
  type        = list(string)
  default     = ["arn:aws:iam::494378024839:user/odl_user_2301881"]
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.250.0.0/16"
}

variable "prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "jtb75"
}
