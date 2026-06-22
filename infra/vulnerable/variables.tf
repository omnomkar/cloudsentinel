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

variable "enable_cloudtrail_resource" {
  description = "Whether to create the aws_cloudtrail resource. Set to false when targeting LocalStack's free tier, which does not support the CloudTrail API. The Terraform file remains intact for static Checkov scanning regardless of this value."
  type        = bool
  default     = true
}
