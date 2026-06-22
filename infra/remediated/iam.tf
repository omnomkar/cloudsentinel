# IAM — remediated
# Fixes: IAM_WILDCARD_ACTION_POLICY
#
# IAM_UNUSED_ROLE and IAM_ACCESS_KEY_AGE are runtime/time-based checks.
# The remediated config avoids creating stale access keys; the role
# is expected to be used (no stale-role resource is created here).

# Scoped policy with explicit actions and resource — passes IAM_WILDCARD_ACTION_POLICY
resource "aws_iam_policy" "wildcard_admin" {
  name        = "cloudsentinel-scoped-policy"
  description = "Least-privilege policy — read-only S3 access to a specific prefix"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ScopedS3Read"
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::cloudsentinel-remediated-data",
          "arn:aws:s3:::cloudsentinel-remediated-data/*"
        ]
      }
    ]
  })
}

# No stale role resource — IAM_UNUSED_ROLE will not fire on a freshly-created
# role that is actually used.  The check fires at runtime after 90 idle days.

# No access key resource — IAM_ACCESS_KEY_AGE will not fire because there are
# no IAM user access keys in this configuration.
resource "aws_iam_user" "legacy_svc" {
  name = "cloudsentinel-remediated-svc"
}
# aws_iam_access_key intentionally omitted — no static long-lived credentials
