terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "security_lab" {
  bucket = "my-bucket"
tags = {
Name = "Security Lab Bucket"
Environment = "Lab"
}
}
resource "aws_s3_bucket" "weak_s3" {
  bucket = "weak-bucket"
tags = {
Name = "Security Lab Weak Bucket"
Environment = "Lab"
}
}

resource "aws_s3_bucket_versioning" "security_lab"{
bucket = aws_s3_bucket.security_lab.id
versioning_configuration {
status = "Enabled"
}
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_lab"{
bucket = aws_s3_bucket.security_lab.id
rule {
apply_server_side_encryption_by_default {
sse_algorithm = "AES256"
}
}
}

resource "aws_s3_bucket_public_access_block" "security_lab"{
bucket = aws_s3_bucket.security_lab.id
block_public_acls = true
block_public_policy  = true
ignore_public_acls = true
restrict_public_buckets = true
}

resource "aws_vpc" "main" {
cidr_block = "10.0.0.0/16"
tags = {
Name = "Lab_VPC"
}
}


resource "aws_subnet" "public_subnet" {
vpc_id = aws_vpc.main.id
cidr_block = "10.0.1.0/24"
tags = {
Name = "Lab_public_subnet"
}
}

resource "aws_subnet" "private_subnet" {
vpc_id = aws_vpc.main.id
cidr_block = "10.0.2.0/24"
tags = {
Name = "Lab_private_subnet"
}
}

resource "aws_internet_gateway" "gw" {
vpc_id = aws_vpc.main.id
tags = {
Name = "Lab_GW"
}
}

resource "aws_route_table" "public_route"{
vpc_id = aws_vpc.main.id
route {
cidr_block = "0.0.0.0/0"
gateway_id = aws_internet_gateway.gw.id
}
tags = {
Name = "public subnet to GW route table"
}
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_route.id
}

resource "aws_security_group" "public_sg"{
name = "public_security_group"
description = "Testing"
vpc_id = aws_vpc.main.id
ingress {
from_port = 50
to_port = 90
protocol = "tcp"
cidr_blocks = ["0.0.0.0/0"]
}
egress{
from_port = 0
to_port = 0
protocol = "-1"
cidr_blocks = ["0.0.0.0/0"]
}
}

resource "aws_security_group" "private_sg"{
name = "private_security_group"
description = "Testing"
vpc_id = aws_vpc.main.id
ingress {
from_port = 10
to_port = 30
protocol = "tcp"
security_groups = [aws_security_group.public_sg.id]
}
egress{
from_port = 0
to_port = 0
protocol = "-1"
cidr_blocks = ["0.0.0.0/0"]
}
}

resource "aws_instance" "ec2_private" {
ami = "ami-0ba259e664698cbfc"
instance_type  = "t2.micro"
subnet_id = aws_subnet.private_subnet.id
vpc_security_group_ids = [aws_security_group.private_sg.id]
tags = {
Name = "Lab_Private_EC2"
}
}

resource "aws_instance" "ec2_public" {
ami = "ami-0ba259e664698cbfc"
instance_type  = "t2.micro"
subnet_id = aws_subnet.public_subnet.id
vpc_security_group_ids = [aws_security_group.public_sg.id]
tags = {
Name = "Lab_Public_EC2"
}
}

resource "aws_iam_policy" "weak_policy" {
name = "weak_test_policy"
description = "Used for testing over-permission"
policy = jsonencode({
Version =  "2012-10-17"
Statement = [
{
Effect = "Allow"
Action = "*"
Resource = "*"
}
]
})
}

resource "aws_iam_policy" "wildcard_policy" {
name = "wildcard_test_policy"
description = "Used for testing over-resource"
policy = jsonencode({
Version =  "2012-10-17"
Statement = [
{
Effect = "Allow"
Action = ["s3:*","ec2:*","s3:Getobject"]
Resource = "*"
}
]
})
}

resource "aws_iam_policy" "broad_policy" {
name = "iam_test_policy"
description = "Used for testing sensitive iam policy"
policy = jsonencode({
Version =  "2012-10-17"
Statement = [
{
Effect = "Allow"
Action = ["iam:CreateUser","iam:AttachUserPolicy","iam:PassRole"]
Resource = "*"
}
]
})
}

resource "aws_iam_policy" "passrole_policy" {
  name        = "passrole-policy"
  description = "Intentionally vulnerable PassRole policy"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      }
    ]
  })
}