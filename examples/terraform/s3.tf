resource "aws_s3_bucket" "s3_bucket_faynosync_apps" {
  bucket = "faynosync-apps"
} 

resource "aws_s3_bucket_ownership_controls" "s3_bucket_faynosync_apps" {
  bucket = aws_s3_bucket.s3_bucket_faynosync_apps.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
resource "aws_s3_bucket_public_access_block" "s3_bucket_faynosync_apps" {
  bucket = aws_s3_bucket.s3_bucket_faynosync_apps.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "s3_bucket_faynosync_apps" {
  bucket = "${aws_s3_bucket.s3_bucket_faynosync_apps.id}"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::faynosync-apps",
                "arn:aws:s3:::faynosync-apps/*"
            ]
        }
    ]
}
POLICY
  depends_on = [aws_s3_bucket_public_access_block.s3_bucket_faynosync_apps]
}
resource "aws_s3_bucket_cors_configuration" "faynosync-app-bucket-apps" {
  bucket = aws_s3_bucket.s3_bucket_faynosync_apps.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET", "DELETE"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}
resource "aws_s3_bucket_acl" "faynosync-app-bucket-apps" {
  depends_on = [aws_s3_bucket_ownership_controls.s3_bucket_faynosync_apps, aws_s3_bucket_public_access_block.s3_bucket_faynosync_apps,]
  bucket = aws_s3_bucket.s3_bucket_faynosync_apps.id
  acl    = "public-read"
}
