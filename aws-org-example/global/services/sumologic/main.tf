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

resource "aws_lambda_function" "sumo_func" {
  function_name = "${var.project}-aws-compliance-${var.environment}-sumoLog"

  # "main" is the filename within the zip file (main.js) and "handler"
  # is the name of the property under which the handler function was
  # exported in that file.
  filename = "build.zip"

  source_code_hash = "${base64sha256(file("build.zip"))}"
  handler          = "src/logger/sumo.handler"

  runtime = "nodejs6.10"

  role = "${aws_iam_role.lambda_exec.arn}"

  vpc_config = {
    subnet_ids         = ["${var.subnet_a_private}", "${var.subnet_b_private}", "${var.subnet_c_private}"]
    security_group_ids = ["${var.lambda_exec_security_group}"]
  }

  environment {
    variables = {
      SUMO_ENDPOINT = "${var.sumo_endpoint}"
    }
  }
}

resource "aws_cloudwatch_log_subscription_filter" "vpc_flowlog_lambdafunction_logfilter" {
  name            = "${var.project}-aws-compliance-${var.environment}-vpc-flowlog-logfilter"
  log_group_name  = "${aws_cloudwatch_log_group.flow_log_group.name}"
  filter_pattern  = ""
  destination_arn = "${aws_lambda_function.sumo_func.arn}"
}

resource "aws_lambda_permission" "allow_cloudwatch_trigger_vpc_flowlog_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.sumo_func.function_name}"
  principal     = "logs.${var.region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.flow_log_group.arn}"
}

# IAM role which dictates what other AWS services the Lambda function
# may access.
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project}-aws-compliance-${var.environment}-lambda-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "lambda_exec_policy" {
  name = "${var.project}-aws-compliance-${var.environment}-flowlog-policy"
  role = "${aws_iam_role.lambda_exec.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
