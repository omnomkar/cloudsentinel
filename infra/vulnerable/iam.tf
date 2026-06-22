# IAM misconfigurations
# Triggers: IAM_WILDCARD_ACTION_POLICY, IAM_UNUSED_ROLE, IAM_ACCESS_KEY_AGE
#
# IAM_ROOT_NO_MFA cannot be reproduced via Terraform — the root account is
# out of scope for any IaC tool by design.  That check fires at scan time when
# the root account in the target AWS environment lacks MFA; LocalStack always
# returns AccountMFAEnabled=0 so it will fire there too.

# Action="*" + Resource="*" — triggers IAM_WILDCARD_ACTION_POLICY
resource "aws_iam_policy" "wildcard_admin" {
  name        = "cloudsentinel-wildcard-admin"
  description = "Intentionally overly permissive policy for misconfiguration demo"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEverything"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Role with no last-used date.  IAM_UNUSED_ROLE fires after 90 days from
# creation when the role has never been used; the check compares against
# reference_time at scan time, not at plan time.
resource "aws_iam_role" "stale_role" {
  name = "cloudsentinel-stale-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# IAM user with an access key.  IAM_ACCESS_KEY_AGE fires at scan time once the
# key is older than 90 days.  Terraform cannot back-date key creation, so in a
# fresh LocalStack environment this check passes until 90 days have elapsed.
# Unit tests inject a synthetic reference_time to simulate old keys.
resource "aws_iam_user" "legacy_svc" {
  name = "cloudsentinel-legacy-svc"
}

resource "aws_iam_access_key" "legacy_svc" {
  user = aws_iam_user.legacy_svc.name
}
