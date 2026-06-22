variable "endpoint_url" {
  description = "Custom endpoint URL for LocalStack or other mock AWS. Empty string uses real AWS endpoints."
  type        = string
  default     = ""
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}
