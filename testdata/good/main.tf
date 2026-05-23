# Same resource shapes as bad/, but configured correctly. Scanner should
# report zero findings on this directory.

resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_security_group" "tight" {
  name = "tight"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  identifier          = "demo"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
  storage_encrypted   = true
}
