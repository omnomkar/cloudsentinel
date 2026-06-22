terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Set var.endpoint_url to point at LocalStack (e.g. "http://localhost:4566").
# An empty string means "use real AWS endpoints" — never apply this vulnerable
# directory against real AWS; use LocalStack or terraform plan only.
provider "aws" {
  region = var.region

  dynamic "endpoints" {
    for_each = var.endpoint_url != "" ? [var.endpoint_url] : []
    content {
      s3           = endpoints.value
      iam          = endpoints.value
      ec2          = endpoints.value
      cloudtrail   = endpoints.value
      sts          = endpoints.value
    }
  }

  # LocalStack does not validate credentials
  access_key                  = var.endpoint_url != "" ? "test" : null
  secret_key                  = var.endpoint_url != "" ? "test" : null
  skip_credentials_validation = var.endpoint_url != "" ? true : false
  skip_metadata_api_check     = var.endpoint_url != "" ? true : false
  skip_requesting_account_id = var.endpoint_url != "" ? true : false
  s3_use_path_style = var.endpoint_url != "" ? true : false
  
}
