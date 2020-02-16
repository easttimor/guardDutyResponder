output "arn" {
  description = "The ARN of the DynamoDB Table"
  value       = aws_dynamodb_table.this.arn
}