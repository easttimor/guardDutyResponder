output "ddb_arn_nacl_tracker" {
  description = "The ARN of the DynamoDB Table"
  value       = module.dynamodb_nacl_tracker.arn
}

output "ddb_arn_block_list" {
  description = "The ARN of the DynamoDB Table"
  value       = module.dynamodb.arn
}