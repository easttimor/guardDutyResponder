# Resource create toggles
variable create_guardduty_responder {}

# Common variables
variable "tags" {
  description = "A map of tags to add to all resources"
  type        = "map"
  default     = {}
}

# Lambda
variable "environment_variables" {
  description = "A map of environments for Lambda"
  type        = "map"
  default     = {}
}