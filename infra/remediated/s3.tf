# S3 — remediated
# Fixes: S3_PUBLIC_ACCESS_BLOCK, S3_PUBLIC_ACL, S3_BUCKET_POLICY_PUBLIC, S3_ENCRYPTION_AT_REST

resource "aws_s3_bucket" "vulnerable_data" {
  bucket        = "cloudsentinel-remediated-data"
  force_destroy = true
}

# All four flags enabled — passes S3_PUBLIC_ACCESS_BLOCK
resource "aws_s3_bucket_public_access_block" "vulnerable_data" {
  bucket = aws_s3_bucket.vulnerable_data.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Private ACL — passes S3_PUBLIC_ACL
resource "aws_s3_bucket_acl" "vulnerable_data" {
  depends_on = [aws_s3_bucket_public_access_block.vulnerable_data]
  bucket     = aws_s3_bucket.vulnerable_data.id
  acl        = "private"
}

# AES256 server-side encryption — passes S3_ENCRYPTION_AT_REST
resource "aws_s3_bucket_server_side_encryption_configuration" "vulnerable_data" {
  bucket = aws_s3_bucket.vulnerable_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No public bucket policy resource — passes S3_BUCKET_POLICY_PUBLIC
