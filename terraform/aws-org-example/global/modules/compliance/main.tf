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

# -------------------------------------------------------------
# S3 bucket to store client's logs
# -------------------------------------------------------------
resource "aws_s3_bucket" "logging_bucket" {
  provider = "aws.logging"
  bucket        = "${var.child-account-bucket}"
  region        = "${var.child-account-region}"
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
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.child-account-bucket}"
        },
        {
            "Sid": "AWSConfigBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "config.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.child-account-bucket}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": [
              "arn:aws:s3:::${var.child-account-bucket}/${var.child-project}-${var.child-account-env}-cloudtrail/AWSLogs/${var.child-account-id}/*"
            ],
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Sid": "AWSConfigWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "config.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": [
              "arn:aws:s3:::${var.child-account-bucket}/${var.child-project}-${var.child-account-env}-config/AWSLogs/${var.child-account-id}/*"
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

resource "aws_s3_bucket_object" "object_cloudtrail" {
  provider = "aws.logging"
  bucket = "${aws_s3_bucket.logging_bucket.id}"
  acl    = "private"
  key    = "${var.child-account-env}-cloudtrail/"
  source = "/dev/null"
}

# -------------------------------------------------------------
# SNS
# -------------------------------------------------------------

resource "aws_sns_topic" "alarms" {
  name = "${var.child-profile}-cloudtrail-topic"
}


resource "aws_flow_log" "vpc_flow_log" {
  provider = "aws.child"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  vpc_id         = "${var.vpc}"
  traffic_type   = "ALL"
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  provider = "aws.child"
  name = "/aws/vpc/${var.child-project}-aws-compliance-${var.child-account-env}-flowlog"
}

resource "aws_iam_role" "flow_log_role" {
  provider = "aws.child"
  name = "${var.child-project}-aws-compliance-${var.child-account-env}-flowlog-role"

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
  provider = "aws.child"
  name = "${var.child-project}-aws-compliance-${var.child-account-env}-flowlog-policy"
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

resource "aws_cloudwatch_log_group" "cloudwatch_log_group" {
  provider = "aws.child"
  name = "${var.child-account-name}-cloudtrail-log-group"
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  provider = "aws.child"
  name           = "UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  provider = "aws.child"
  alarm_name                = "UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.unauthorized_api_calls.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "no_mfa_console_signin" {
  provider = "aws.child"
  name           = "NoMFAConsoleSignin"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "NoMFAConsoleSignin"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "no_mfa_console_signin" {
  provider = "aws.child"
  alarm_name                = "NoMFAConsoleSignin"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.no_mfa_console_signin.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  provider = "aws.child"
  name           = "RootUsage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "RootUsage"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  provider = "aws.child"
  alarm_name                = "RootUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.root_usage.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "IAMChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "IAMChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  provider = "aws.child"
  alarm_name                = "IAMChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.iam_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_cfg_changes" {
  name           = "CloudTrailCfgChanges"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "CloudTrailCfgChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg_changes" {
  provider = "aws.child"
  alarm_name                = "CloudTrailCfgChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "console_signin_failures" {
  provider = "aws.child"
  name           = "ConsoleSigninFailures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "ConsoleSigninFailures"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  provider = "aws.child"
  alarm_name                = "ConsoleSigninFailures"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.console_signin_failures.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "disable_or_delete_cmk" {
  provider = "aws.child"
  name           = "DisableOrDeleteCMK"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "DisableOrDeleteCMK"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "disable_or_delete_cmk" {
  provider = "aws.child"
  alarm_name                = "DisableOrDeleteCMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.disable_or_delete_cmk.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  provider = "aws.child"
  name           = "S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  provider = "aws.child"
  alarm_name                = "S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "aws_config_changes" {
  provider = "aws.child"
  name           = "AWSConfigChanges"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "AWSConfigChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  provider = "aws.child"
  alarm_name                = "AWSConfigChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.aws_config_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "SecurityGroupChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  provider = "aws.child"
  alarm_name                = "SecurityGroupChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.security_group_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  provider = "aws.child"
  name           = "NACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "NACLChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  provider = "aws.child"
  alarm_name                = "NACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.nacl_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "network_gw_changes" {
  provider = "aws.child"
  name           = "NetworkGWChanges"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "NetworkGWChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_gw_changes" {
  provider = "aws.child"
  alarm_name                = "NetworkGWChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.network_gw_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  provider = "aws.child"
  name           = "RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  provider = "aws.child"
  alarm_name                = "RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.route_table_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  provider = "aws.child"
  name           = "VPCChanges"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"

  metric_transformation {
    name      = "VPCChanges"
    namespace = "${var.child-account-name}-cis-metric"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  provider = "aws.child"
  alarm_name                = "VPCChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.vpc_changes.id}"
  namespace                 = "${var.child-account-name}-cis-metric"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = ["${aws_sns_topic.alarms.arn}"]
  insufficient_data_actions = []
}

# -------------------------------------------------------------
# KMS
# -------------------------------------------------------------

resource "aws_kms_key" "cloudtrail" {
  provider = "aws.child"
  description             = "cloudtrail"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "key-default-1",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": [ "arn:aws:iam::${var.child-account-id}:root",
                 "arn:aws:iam::${var.logging-account-id}:root" ]
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to encrypt loggings",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:GenerateDataKey*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.child-account-id}:trail/*"
        }
      }
    }
  ]
}
POLICY
}

resource "aws_kms_alias" "cloudtrail" {
  provider = "aws.child"
  name          = "alias/cloudtrail"
  target_key_id = "${aws_kms_key.cloudtrail.key_id}"
}

# -------------------------------------------------------------
# Cloudtrail
# -------------------------------------------------------------
resource "aws_cloudtrail" "cloudtrail" {
  provider = "aws.logging"
  name                          = "${var.child-account-env}-cloudtrail"
  s3_bucket_name                = "${var.child-account-bucket}"
  s3_key_prefix                 = "${var.child-account-env}-cloudtrail/"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "${aws_kms_key.cloudtrail.arn}"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudwatch_log_group.arn}"
  cloud_watch_logs_role_arn     = "${aws_iam_role.cloudwatch_delivery.arn}"
  depends_on                    = ["aws_s3_bucket.logging_bucket"]
}

resource "aws_iam_role" "cloudwatch_delivery" {
  provider = "aws.child"
  name = "${var.child-profile}-cloudwatch-delivery-role"

  assume_role_policy = <<END_OF_POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
END_OF_POLICY
}

resource "aws_iam_role_policy" "cloudwatch_delivery_policy" {
  provider = "aws.child"
  name = "${var.child-profile}-cloudwatch-delivery-policy"
  role = "${aws_iam_role.cloudwatch_delivery.id}"

  policy = <<END_OF_POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailCreateLogStream2014110",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream"
      ],
      "Resource": [
        "arn:aws:logs:*:${var.child-account-id}:log-group:${aws_cloudwatch_log_group.cloudwatch_log_group.name}:log-stream:*"
      ]
    },
    {
      "Sid": "AWSCloudTrailPutLogEvents20141101",
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:${var.child-account-id}:log-group:${aws_cloudwatch_log_group.cloudwatch_log_group.name}:log-stream:*"
      ]
    }
  ]
}
END_OF_POLICY
}