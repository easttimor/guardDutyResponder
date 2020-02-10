# PROVIDERS
provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "this" {}


# 
locals {

  # DynamoDB
  dynamodb_table_name_block_list = "guardduty_responder_block_list"
  dynamodb_table_name_nacl       = "guardduty_responder_nacl_tracker"


  create_guardduty_responder = true
  tags = {
    project       = "Circus"
    resourceOwner = ""
    environment   = "Demo"
  }
  environment_variables = {
    LOG_LEVEL          = "info"
    DDB_BLOCK_LIST     = local.dynamodb_table_name_block_list
    IP_WHITELIST       = ""
    DAY_THRESHOLD      = "30"
    CROSS_ACCOUNT_ROLE = "cross_account_admin"
    NACL_RULE_NUM      = "1"
    DDB_NACL           = local.dynamodb_table_name_nacl
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

# terraform import module.dynamodb.aws_dynamodb_table.this guardduty_responder_block_list
module "dynamodb" {
  source = "./modules/dynamodb"

  ddb_table_name    = local.dynamodb_table_name_block_list
  ddb_partition_key = "instanceId"
  ddb_range_key     = "remoteIp"
  ddb_attribute_ttl = "TTL"

  # capacity
  ddb_read_capacity  = 5
  ddb_write_capacity = 5
}

module "dynamodb_nacl_tracker" {
  source = "./modules/dynamodb"

  ddb_table_name    = local.dynamodb_table_name_nacl
  ddb_partition_key = "naclId"
  ddb_range_key     = "accountId"

  # capacity
  ddb_read_capacity  = 5
  ddb_write_capacity = 5
}