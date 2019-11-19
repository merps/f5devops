terraform {
  required_version = ">= 0.10.3" # introduction of Local Values configuration language feature
}
/*
provider "aws" {
  alias          = "parent"
  region         = "${var.aws-region}"
  profile        = "${var.parent-profile}"
  assume_role {
    role_arn     = "arn:aws:iam::${var.child-account-id}:role/DdevopsCrossAccountAdmins"
  }
}

provider "aws" {
  alias          = "child"
  region         = "${var.aws-region}"
  profile        = "${var.parent-profile}"
  assume_role {
    role_arn     = "arn:aws:iam::${var.child-account-id}:role/DdevopsCrossAccountAdmins"
  }
}

provider "aws" {
  alias          = "logging"
  region         = "${var.aws-region}"
  profile        = "${var.parent-profile}"
  assume_role {
    role_arn     = "arn:aws:iam::${var.logging-account-id}:role/DdevopsCrossAccountAdmins"
  }
}
*/

resource "aws_flow_log" "vpc_flow_log" {
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  vpc_id         = "${var.vpc}"
  traffic_type   = "ALL"
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name = "/aws/vpc/${var.project}-aws-compliance-${var.environment}-flowlog"
}

resource "aws_iam_role" "flow_log_role" {
  name = "${var.project}-aws-compliance-${var.environment}-flowlog-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "${var.project}-aws-compliance-${var.environment}-flowlog-policy"
  role = "${aws_iam_role.flow_log_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
