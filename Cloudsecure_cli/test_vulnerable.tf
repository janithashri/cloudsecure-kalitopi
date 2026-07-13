provider "aws" {
  region = "us-east-1"
}

# VULNERABILITY: Hardcoded Credentials
resource "aws_db_instance" "default" {
  allocated_storage    = 10
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  db_name              = "mydb"         # Changed from 'name' to 'db_name'
  username             = "admin"
  password             = "P@ssword123!" # tfsec will catch this!
  skip_final_snapshot  = true
}

# VULNERABILITY: Public S3 Bucket 
resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket-cloud-secure"
}

# This is the modern way to set ACLs, but it's still "public-read" (Vulnerable!)
resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read" 
}