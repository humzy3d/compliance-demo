# Demo infrastructure, remediated after the compliance-agents gates flagged it.
# Never applied without credentials.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" { region = "us-east-1" }

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------- encryption key (KSI-SVC-ASM / PCI 3.6)

resource "aws_kms_key" "data" {
  description         = "CMK for cardholder exports and payments DB"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdmin"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

# ---------------------------------------------------------------- cardholder export bucket

resource "aws_s3_bucket" "cardholder_exports" {
  bucket = "demo-cardholder-exports"
}

resource "aws_s3_bucket_public_access_block" "cardholder_exports" {
  bucket                  = aws_s3_bucket.cardholder_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cardholder_exports" {
  bucket = aws_s3_bucket.cardholder_exports.id
  rule { object_ownership = "BucketOwnerEnforced" } # disables ACLs entirely
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cardholder_exports" {
  bucket = aws_s3_bucket.cardholder_exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "cardholder_exports" {
  bucket = aws_s3_bucket.cardholder_exports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "cardholder_exports" {
  bucket        = aws_s3_bucket.cardholder_exports.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cardholder-exports/"
}

resource "aws_s3_bucket_lifecycle_configuration" "cardholder_exports" {
  bucket = aws_s3_bucket.cardholder_exports.id
  rule {
    id     = "expire-exports"
    status = "Enabled"
    filter {}
    expiration { days = 90 } # PCI 3.2.1: keep cardholder data only as long as needed
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

# ---------------------------------------------------------------- access-log bucket (PCI 10.2.1)

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_145:S3 server access log delivery only supports SSE-S3 on the target bucket
  bucket = "demo-cardholder-exports-access-logs"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" } # S3 log delivery does not support SSE-KMS
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "retain-logs-1y"
    status = "Enabled"
    filter {}
    expiration { days = 365 } # PCI 10.5.1: retain audit logs for at least 12 months
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

# ---------------------------------------------------------------- network

resource "aws_security_group" "api" {
  name        = "demo-api"
  description = "Payments API: HTTPS from the load balancer only"

  ingress {
    description = "HTTPS from internal load balancer subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "HTTPS to AWS APIs and the database subnet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

# ---------------------------------------------------------------- database

resource "aws_db_parameter_group" "payments" {
  name   = "demo-payments-pg17"
  family = "postgres17"

  parameter {
    name  = "rds.force_ssl" # encryption in transit
    value = "1"
  }
  parameter {
    name  = "log_statement" # query logging (PCI 10.2)
    value = "ddl"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "demo-rds-enhanced-monitoring"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "monitoring.rds.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "payments" {
  identifier                          = "demo-payments"
  engine                              = "postgres"
  engine_version                      = "17"
  instance_class                      = "db.t4g.micro"
  allocated_storage                   = 20
  username                            = "app"
  manage_master_user_password         = true
  parameter_group_name                = aws_db_parameter_group.payments.name
  vpc_security_group_ids              = [aws_security_group.api.id]
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.data.arn
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 14
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  ca_cert_identifier                  = "rds-ca-rsa2048-g1"
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  monitoring_interval                 = 60
  monitoring_role_arn                 = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.data.arn
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "demo-payments-final"
}
