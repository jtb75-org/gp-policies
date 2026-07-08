# Set the status of key to evaluate 
variable "key_status" {
  type        = list(string)
  description = "Status of key to check for: Active or Inactive"
  default = [
    "Active"
  ]
}

# This control evaluates IAM user with expired access keys that are pending disablement
resource "wiz_control" "inactive_access_keys_pending_disablement" {
  name        = "GP - IAM user with expired access keys that are pending disablement"
  description = "Evaluates if an IAM user has expired access keys that are pending disablement."
  severity    = "LOW"
  query = jsonencode(
    {
      "relationships" : [
        {
          "type" : [
            {
              "type" : "OWNS"
            }
          ],
          "with" : {
            "select" : true,
            "type" : [
              "ACCESS_KEY"
            ],
            "where" : {
              "inactiveTimeframe" : {
                "EQUALS" : [
                  "InTheLast90Days"
                ]
              },
              "status" : {
                "EQUALS" : var.key_status
              }
            }
          }
        }
      ],
      "select" : true,
      "type" : [
        "USER_ACCOUNT"
      ],
      "where" : {
        "nativeType" : {
          "EQUALS" : [
            "user"
          ]
        }
      }
    }
  )

  resolution_recommendation = "Apply the missing required tags to the RDS instance."
}
