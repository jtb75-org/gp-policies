# Set the required account tags to be evaluated
variable "required_org_tags" {
  type = list(object({
    key   = string
    value = string
  }))
  description = "List of required organization tags for AWS accounts"
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

# This control looks at all accounts (AWS or otherwise) to evaluate if the account has the required tags (set above).
resource "wiz_control" "aws_account_missing_org_tags" {
  name        = "GP - Subscription missing required tags"
  description = "Evaluates if an AWS Account is missing any of the required dynamic organization tags."
  severity    = "LOW"
  query = jsonencode(
    {
      "type" : [
        "SUBSCRIPTION"
      ],
      "select" : true,
      "where" : {
        "tags" : {
          "TAG_DOES_NOT_CONTAIN_ANY" : var.required_org_tags
        }
      }
    }
  )

  resolution_recommendation = "Apply the missing required organization tags to the AWS Account."
}
