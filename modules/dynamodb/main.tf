resource "aws_dynamodb_table" "this" {

  name           = var.ddb_table_name
  read_capacity  = var.ddb_read_capacity
  write_capacity = var.ddb_write_capacity
  hash_key       = var.ddb_partition_key
  range_key      = var.ddb_sort_key

  attribute {
    name = var.ddb_partition_key
    type = "S"
  }

  attribute {
    name = var.ddb_sort_key
    type = "S"
  }

  ttl {
    attribute_name = var.ddb_attribute_ttl
    enabled        = true
  }
}