# S3 misconfigurations
# Triggers: S3_PUBLIC_ACCESS_BLOCK, S3_PUBLIC_ACL, S3_BUCKET_POLICY_PUBLIC, S3_ENCRYPTION_AT_REST

resource "aws_s3_bucket" "vulnerable_data" {
  bucket        = "cloudsentinel-vulnerable-data"
  force_destroy = true
}

# All four public-access-block flags disabled — triggers S3_PUBLIC_ACCESS_BLOCK
resource "aws_s3_bucket_public_access_block" "vulnerable_data" {
  bucket = aws_s3_bucket.vulnerable_data.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# Public-read ACL — triggers S3_PUBLIC_ACL
resource "aws_s3_bucket_acl" "vulnerable_data" {
  depends_on = [aws_s3_bucket_public_access_block.vulnerable_data]
  bucket     = aws_s3_bucket.vulnerable_data.id
  acl        = "public-read"
}

# Wildcard principal with no Condition block — triggers S3_BUCKET_POLICY_PUBLIC
resource "aws_s3_bucket_policy" "vulnerable_data" {
  depends_on = [aws_s3_bucket_public_access_block.vulnerable_data]
  bucket     = aws_s3_bucket.vulnerable_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable_data.arn}/*"
        # No Condition block — any condition (e.g. aws:sourceVpc) would
        # restrict exposure and cause the check to PASS.
      }
    ]
  })
}

# No aws_s3_bucket_server_side_encryption_configuration resource — triggers S3_ENCRYPTION_AT_REST
