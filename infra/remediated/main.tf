# =============================================================================
# CloudSentinel — remediated Terraform configuration
# =============================================================================
# PURPOSE: Correctly-configured mirror of ../vulnerable/.  Every resource here
# has the same name and type as its vulnerable counterpart but is configured
# according to AWS security best practices, so that CloudSentinel's 16 scanner
# checks all PASS.
#
# Key differences from ../vulnerable/:
#   S3       — public access block fully enabled, private ACL, no public
#              bucket policy, AES256 server-side encryption enabled
#   IAM      — scoped policy (no wildcard actions/resources)
#   CloudTrail — logging enabled, log file validation enabled, S3 bucket
#              has AES256 encryption
#   Security Groups — SSH/RDP restricted to var.admin_cidr, no unrestricted
#              egress, narrow port ranges only
# =============================================================================
