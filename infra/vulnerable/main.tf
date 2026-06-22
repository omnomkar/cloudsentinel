# =============================================================================
# CloudSentinel — vulnerable Terraform configuration
# =============================================================================
# PURPOSE: Intentionally misconfigured AWS resources that trigger every one of
# CloudSentinel's 16 scanner checks (S3, IAM, CloudTrail, Security Groups).
#
# THIS DIRECTORY IS NEVER MEANT TO BE APPLIED AGAINST REAL AWS.
# Use LocalStack ("terraform apply -var endpoint_url=http://localhost:4566") or
# "terraform plan" only. Applying these resources to a real AWS account would
# create genuinely insecure infrastructure.
#
# For the correctly-configured mirror of these resources, see ../remediated/.
# =============================================================================
