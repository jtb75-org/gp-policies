# Set the required EBS/EC2 tags to be evaluated
variable "required_ebs_tags" {
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
resource "wiz_control" "ebs_volume_missing_required_tags" {
  name        = "GP - EBS volume missing required tags"
  description = "Evaluates if an EBS volume is missing any of the required tags."
  severity    = "LOW"
  query = jsonencode(
    {
      "type" : [
        "VOLUME"
      ],
      "select" : true,
      "where" : {
        "tags" : {
          "TAG_DOES_NOT_CONTAIN_ANY" : var.required_ebs_tags
        }
      },
      "relationships" : [
        {
          "type" : [
            {
              "type" : "USES",
              "reverse" : true
            }
          ],
          "with" : {
            "type" : [
              "VIRTUAL_MACHINE"
            ],
            "select" : true,
            "where" : {
              "tags" : {
                "TAG_CONTAINS_ALL" : var.required_ebs_tags
              }
            }
          }
        }
      ]
    }
  )

  resolution_recommendation = "Apply the missing required tags to the RDS instance."
}
