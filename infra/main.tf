# Demo infrastructure with intentional misconfigurations. Never applied without credentials.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" { region = "us-east-1" }

resource "aws_s3_bucket" "cardholder_exports" {
  bucket = "demo-cardholder-exports"
}

resource "aws_s3_bucket_acl" "cardholder_exports" {
  bucket = aws_s3_bucket.cardholder_exports.id
  acl    = "public-read"
}

resource "aws_security_group" "api" {
  name = "demo-api"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "payments" {
  identifier          = "demo-payments"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "app"
  manage_master_user_password = true
  skip_final_snapshot = true
}
