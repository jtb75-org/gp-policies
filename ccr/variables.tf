variable "prefix" {
  description = "Prefix for Wiz resources and rules"
  type        = string
  default     = "jtb75"
}

variable "target_project_id" {
  description = "Wiz Project ID to scope the rules to (optional)"
  type        = string
  default     = null
}

locals {
  scope_project_id = var.target_project_id == "" ? null : var.target_project_id
}
