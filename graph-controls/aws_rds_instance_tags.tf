# Set the required RDS instance tags to be evaluated
variable "required_rds_tags" {
  type = list(object({
    key   = string
    value = string
  }))
  description = "List of required tags for RDS instances"
  default = [
    {
      key   = "owner"
      value = ""
    },
    {
      key   = "environment"
      value = ""
    },
    {
      key   = "cost-center"
      value = ""
    }
  ]
}

# This control evaluates RDS instances to check if the required tags (set above) are present.
resource "wiz_control" "rds_instance_missing_required_tags" {
  name        = "GP - RDS instance missing required tags"
  description = "Evaluates if an RDS instance is missing any of the required tags."
  severity    = "LOW"
  query = jsonencode(
    {
      "type" : [
        "DB_SERVER"
      ],
      "select" : true,
      "where" : {
        "tags" : {
          "TAG_DOES_NOT_CONTAIN_ANY" : var.required_rds_tags
        }
      }
    }
  )

  resolution_recommendation = "Apply the missing required tags to the RDS instance."
}
