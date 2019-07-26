output "bucket_name_for_cloudtrail" {
  value = "${aws_s3_bucket.logging_bucket.id}"
}

/*
output "bucket_name_for_config" {
  value = "${aws_s3_bucket.strut_worm_config.id}"
}
*/

