# Security Groups — remediated
# Fixes: SG_SSH_OPEN_TO_WORLD, SG_RDP_OPEN_TO_WORLD,
#        SG_UNRESTRICTED_EGRESS, SG_OVERLY_PERMISSIVE

resource "aws_vpc" "vulnerable" {
  cidr_block = "10.0.0.0/16"
}

# SSH restricted to var.admin_cidr — passes SG_SSH_OPEN_TO_WORLD
# Egress restricted to HTTPS only — passes SG_UNRESTRICTED_EGRESS
resource "aws_security_group" "ssh_open" {
  name        = "cloudsentinel-ssh-restricted"
  description = "SSH restricted to admin CIDR only"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    description = "SSH from admin CIDR only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDP restricted to var.admin_cidr — passes SG_RDP_OPEN_TO_WORLD
resource "aws_security_group" "rdp_open" {
  name        = "cloudsentinel-rdp-restricted"
  description = "RDP restricted to admin CIDR only"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    description = "RDP from admin CIDR only"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Narrow port range (443 only) — passes SG_OVERLY_PERMISSIVE
resource "aws_security_group" "wide_port_range" {
  name        = "cloudsentinel-narrow-ports"
  description = "Single specific port only — no wide ranges"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    description = "HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
