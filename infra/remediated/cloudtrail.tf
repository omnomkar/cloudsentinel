# CloudTrail — remediated
# Fixes: CLOUDTRAIL_LOGGING_DISABLED, CLOUDTRAIL_LOG_VALIDATION_OFF,
#        CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT

# Destination bucket with AES256 encryption — passes CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudsentinel-cloudtrail-logs-remed"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# AES256 encryption on the log bucket — passes CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
  bucket     = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# Trail with logging and log file validation both enabled
# Passes: CLOUDTRAIL_LOGGING_DISABLED, CLOUDTRAIL_LOG_VALIDATION_OFF
resource "aws_cloudtrail" "remediated" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  name                       = "cloudsentinel-remediated-trail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail_logs.id
  enable_logging             = true   # Passes: CLOUDTRAIL_LOGGING_DISABLED
  enable_log_file_validation = true   # Passes: CLOUDTRAIL_LOG_VALIDATION_OFF
}
