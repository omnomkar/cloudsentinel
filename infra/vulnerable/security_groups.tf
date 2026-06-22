# Security Group misconfigurations
# Triggers: SG_SSH_OPEN_TO_WORLD, SG_RDP_OPEN_TO_WORLD,
#           SG_UNRESTRICTED_EGRESS, SG_OVERLY_PERMISSIVE

resource "aws_vpc" "vulnerable" {
  cidr_block = "10.0.0.0/16"
}

# Port 22 open from 0.0.0.0/0 — triggers SG_SSH_OPEN_TO_WORLD
# Unrestricted egress (-1 protocol) — triggers SG_UNRESTRICTED_EGRESS
resource "aws_security_group" "ssh_open" {
  name        = "cloudsentinel-ssh-open"
  description = "Demo: SSH open to the world — intentionally misconfigured"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Unrestricted egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Port 3389 open from 0.0.0.0/0 — triggers SG_RDP_OPEN_TO_WORLD
# Unrestricted egress — triggers SG_UNRESTRICTED_EGRESS
resource "aws_security_group" "rdp_open" {
  name        = "cloudsentinel-rdp-open"
  description = "Demo: RDP open to the world — intentionally misconfigured"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Unrestricted egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Port range 1-65535 from 0.0.0.0/0 — triggers SG_OVERLY_PERMISSIVE (range > 1024)
# Also triggers SG_UNRESTRICTED_EGRESS
resource "aws_security_group" "wide_port_range" {
  name        = "cloudsentinel-wide-ports"
  description = "Demo: overly wide port range — intentionally misconfigured"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    description = "Overly wide port range from anywhere"
    from_port   = 1
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Unrestricted egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
