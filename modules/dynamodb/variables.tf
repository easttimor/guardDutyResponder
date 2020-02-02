variable "ddb_table_name" {
  description = ""
  type        = string
  default     = ""
}

variable "ddb_sort_key" {
  description = ""
  type        = string
  default     = ""
}

variable "ddb_partition_key" {
  description = ""
  type        = string
  default     = ""
}

variable "ddb_attribute_ttl" {
  description = ""
  type        = string
  default     = "TTL"
}

variable "ddb_read_capacity" {
  description = ""
  type        = string
  default     = 20
}

variable "ddb_write_capacity" {
  description = ""
  type        = string
  default     = 20
}