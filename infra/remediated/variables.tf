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

variable "admin_cidr" {
  description = "CIDR block for SSH/RDP admin access to compute resources. Replace with your organisation's actual IP range."
  type        = string
  default     = "10.0.0.0/8"
  # Replace this default with a specific CIDR that matches your admin IP range
  # before applying in any environment. "10.0.0.0/8" is a placeholder for
  # internal/VPN-only access patterns.
}
