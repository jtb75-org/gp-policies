terraform {
  required_providers {
    wiz = {
      source  = "tf.app.wiz.io/wizsec/wiz"
      version = ">= 1.0"
    }
  }

  backend "s3" {
    key            = "ccr/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}

# Authentication via environment variables:
#   WIZ_CLIENT_ID
#   WIZ_CLIENT_SECRET
provider "wiz" {}
