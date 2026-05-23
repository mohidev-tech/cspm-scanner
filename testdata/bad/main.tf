# Each resource here is wrong on purpose. The scanner must catch all of them.

resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  identifier          = "demo"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_iam_policy" "wildcard" {
  name = "wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow"
        "Action": "*"
        "Resource": "*"
      }
    ]
  })
}
