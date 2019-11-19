terraform {
  required_version = ">= 0.10.3" # introduction of Local Values configuration language feature
  backend "s3" {
  }
}

data "terraform_remote_state" "remote_state" {
  backend = "s3"
  config {
  }
}

resource "aws_s3_bucket" "strut_worm_config" {
  provider      = "${var.logging-account-id}"
  bucket        = "${var.child-account-name}-config"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSConfigBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "config.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.child-account-name}-config"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "config.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": [
              "arn:aws:s3:::${var.child-account-name}-config/AWSLogs/${var.child-account-id}/*"
            ],
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_config_delivery_channel" "config_delivery_channel" {
  name           = "config_delivery_channel"
  s3_bucket_name = "${aws_s3_bucket.strut_worm_config.id}"
  depends_on     = ["aws_config_configuration_recorder.config_configuration_recorder"]
}

resource "aws_config_configuration_recorder" "config_configuration_recorder" {
  name     = "config_configuration_recorder"
  role_arn = "${aws_iam_role.config-role.arn}"

  recording_group = {
    all_supported                 = "true"
    include_global_resource_types = "true"
  }
}

resource "aws_config_configuration_recorder_status" "config_configuration_recorder_status" {
  name       = "${aws_config_configuration_recorder.config_configuration_recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.config_delivery_channel"]
}

resource "aws_iam_role" "config-role" {
  name = "config-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "config_policy" {
  name = "config_policy"
  role = "${aws_iam_role.config-role.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement":
   [

     {
       "Effect": "Allow",
       "Action": ["s3:PutObject"],
       "Resource": ["${aws_s3_bucket.strut_worm_config.arn}/AWSLogs/*"],
       "Condition":
        {
          "StringLike":
            {
              "s3:x-amz-acl": "bucket-owner-full-control"
            }
        }
     },
     {
       "Effect": "Allow",
       "Action": ["s3:GetBucketAcl"],
       "Resource": "${aws_s3_bucket.strut_worm_config.arn}"
     }
  ]
  }
POLICY
}

resource "aws_iam_policy_attachment" "AWSConfigRole" {
  name       = "AWSConfigRole"
  roles      = ["${aws_iam_role.config-role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}
