# PROVIDERS
provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "this" {}

# 
locals {
  create_guardduty_responder = true
  tags = {
    project       = "Circus"
    resourceOwner = ""
    environment   = "Demo"
  }
  environment_variables = {
    LOG_LEVEL = "info"
  }
}

# Module creates the following event flow
# Source: GuardDuty Finding
# Target: Lambda processing function
# Result: Source IP blocked somehow
module "guardduty_responder" {
  source = "./modules/guardduty_responder"

  create_guardduty_responder = local.create_guardduty_responder
  environment_variables      = local.environment_variables
  tags                       = local.tags
}