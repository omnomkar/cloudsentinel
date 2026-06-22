# CloudTrail misconfigurations
# Triggers: CLOUDTRAIL_LOGGING_DISABLED, CLOUDTRAIL_LOG_VALIDATION_OFF,
#           CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT
#
# CLOUDTRAIL_NO_TRAIL fires when no trail exists at all.  This file creates a
# trail (with logging disabled) so the other three checks can fire.  To trigger
# CLOUDTRAIL_NO_TRAIL instead, remove the aws_cloudtrail resource.

# Destination bucket for CloudTrail logs — no encryption configured
# Triggers: CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT (no SSE on the trail's S3 bucket)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudsentinel-cloudtrail-logs-vuln"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Required bucket policy so CloudTrail can write to the bucket
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

# Trail with logging disabled and no log file validation
# Triggers: CLOUDTRAIL_LOGGING_DISABLED, CLOUDTRAIL_LOG_VALIDATION_OFF
resource "aws_cloudtrail" "vulnerable" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  name                       = "cloudsentinel-vulnerable-trail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail_logs.id
  enable_logging             = false  # Triggers: CLOUDTRAIL_LOGGING_DISABLED
  enable_log_file_validation = false  # Triggers: CLOUDTRAIL_LOG_VALIDATION_OFF
  # No kms_key_id and bucket has no SSE — triggers CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT
}
