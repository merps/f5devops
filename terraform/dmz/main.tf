terraform {
  backend "s3" {}
}

provider "aws" {
  alias   = "child"
  profile = "${var.child-profile}"
  region  = "${var.aws-region}"

  /*
  assume_role {
    role_arn = "arn:aws:iam::${var.child-account-id}:role/${var.admin-role}"
  }
*/
}

provider "aws" {
  alias   = "logging"
  profile = "${var.logging-profile}"
  region  = "${var.aws-region}"

  /*
  assume_role {
    role_arn = "arn:aws:iam::${var.logging-account-id}:role/${var.admin-role}"
  }
*/
}

module "vpc" {
  source = "../global/modules/vpc"

  providers = {
    aws = "aws.child"
  }

  name = "${var.project}-${var.environment}"
  cidr = "10.4.0.0/22"

  azs            = ["ap-southeast-2a", "ap-southeast-2b", "ap-southeast-2c"]
  public_subnets = ["10.4.0.0/27", "10.4.0.32/27", "10.4.0.64/27"]

  enable_nat_gateway = false
  enable_vpn_gateway = false

  tags = {
    Terraform   = "true"
    Environment = "${var.environment}"
  }
}

/*
module "worm" {
  source = "../global/modules/worm"

  providers = {
    aws = "aws.logging"
  }

  child-account-bucket = "${var.project}-${var.environment}"
  child-project        = "${var.project}"
  child-account-id     = "${var.child-account-id}"
  child-account-env    = "${var.environment}"
  child-account-region = "${var.aws-region}"
} */

/* module "compliance" {
  source = "../global/modules/compliance"

  providers = {
    aws = "aws.child"
    aws = "aws.logging"
  }

  vpc                  = "${module.vpc.vpc_id}"
  parent-account-id    = "${var.parent-account-id}"
  child-project        = "${var.project}"
  parent-profile       = "${var.parent-profile}"
  child-account-bucket = "${var.project}-${var.environment}"
  child-profile        = "${var.child-profile}"
  child-account-name   = "${var.project}-${var.environment}"
  child-account-id     = "${var.child-account-id}"
  child-account-env    = "${var.environment}"
  child-account-region = "${var.aws-region}"
  logging-account-id   = "${var.logging-account-id}"
}

*/

############################################################
## DMZ stanza
############################################################
resource "aws_network_acl" "nacl_dmz" {
  provider   = "aws.child"
  vpc_id     = "${module.vpc.vpc_id}"
  subnet_ids = ["${module.vpc.public_subnets}"]

  ingress {
    from_port  = 0
    to_port    = 0
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.1.0.0/22"
  }

  ingress {
    from_port  = 0
    to_port    = 0
    rule_no    = 102
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.2.0.0/22"
  }

  ingress {
    from_port  = 0
    to_port    = 0
    rule_no    = 103
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.3.0.0/16"
  }

  ingress {
    from_port  = 22
    to_port    = 22
    rule_no    = 200
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  ingress {
    from_port  = 80
    to_port    = 80
    rule_no    = 300
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  ingress {
    from_port  = 443
    to_port    = 443
    rule_no    = 400
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  ingress {
    from_port  = 1024
    to_port    = 65535
    rule_no    = 500
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  egress {
    from_port  = 0
    to_port    = 0
    rule_no    = 101
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.1.0.0/22"
  }

  egress {
    from_port  = 0
    to_port    = 0
    rule_no    = 102
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.2.0.0/22"
  }

  egress {
    from_port  = 0
    to_port    = 0
    rule_no    = 103
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.3.0.0/16"
  }

  egress {
    from_port  = 22
    to_port    = 22
    rule_no    = 200
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  egress {
    from_port  = 80
    to_port    = 80
    rule_no    = 300
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  egress {
    from_port  = 443
    to_port    = 443
    rule_no    = 400
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  egress {
    from_port  = 1024
    to_port    = 65535
    rule_no    = 500
    action     = "allow"
    protocol   = "6"
    cidr_block = "0.0.0.0/0"
  }

  tags {
    "Name" = "nacl_${var.project}-${var.environment}"
  }
}

resource "aws_security_group" "sg_dmz_f5" {
  provider    = "aws.child"
  name        = "sg_${var.project}-${var.environment}_f5"
  description = "Security Group for internet facing F5"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    "Name" = "sg_${var.project}-${var.environment}_f5"
  }
}

resource "aws_launch_configuration" "lc_dmz_f5" {
  provider             = "aws.child"
  name                 = "lc_${var.project}-${var.environment}_f5"
  image_id             = "ami-89b76feb"
  instance_type        = "t2.medium"
  iam_instance_profile = "iam_${var.project}-${var.environment}_linux"
  key_name             = "kp_${var.project}-${var.environment}_linux"
  security_groups      = ["${aws_security_group.sg_dmz_f5.id}"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 42
    delete_on_termination = true
  }
}

resource "aws_lb" "nlb-dmz" {
  provider                         = "aws.child"
  internal                         = false
  load_balancer_type               = "network"
  enable_cross_zone_load_balancing = true
  name                             = "elb-${var.project}-${var.environment}-internet"
  enable_deletion_protection       = false

  subnet_mapping {
    subnet_id     = "${module.vpc.public_subnets[0]}"
    allocation_id = "${var.static_eips[0]}"
  }

  subnet_mapping {
    subnet_id     = "${module.vpc.public_subnets[1]}"
    allocation_id = "${var.static_eips[1]}"
  }

  subnet_mapping {
    subnet_id     = "${module.vpc.public_subnets[2]}"
    allocation_id = "${var.static_eips[2]}"
  }
}

resource "aws_autoscaling_group" "asg_dmz_f5" {
  provider                  = "aws.child"
  desired_capacity          = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  launch_configuration      = "${aws_launch_configuration.lc_dmz_f5.name}"
  max_size                  = 1
  min_size                  = 1
  name                      = "asg_${var.project}-${var.environment}_f5"
  vpc_zone_identifier       = ["${module.vpc.public_subnets}"]
  target_group_arns         = ["${aws_lb_target_group.nlb_target_group.arn}"]

  lifecycle {
    create_before_destroy = true
  }

  tag {
    key                 = "Environment"
    value               = "${var.environment}"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "${var.project}-${var.environment}-f5"
    propagate_at_launch = true
  }
}

resource "aws_lb_target_group" "nlb_target_group" {
  provider   = "aws.child"
  depends_on = ["aws_lb.nlb-dmz"]
  name       = "tg-${var.project}-${var.environment}"
  port       = "${var.nlb_svc_port}"
  protocol   = "${var.nlb_listener_protocol}"
  vpc_id     = "${module.vpc.vpc_id}"
}

resource "aws_lb_listener" "nlb_listener" {
  provider          = "aws.child"
  depends_on        = ["aws_lb.nlb-dmz"]
  load_balancer_arn = "${aws_lb.nlb-dmz.id}"
  port              = "${var.nlb_svc_port}"
  protocol          = "${var.nlb_listener_protocol}"

  default_action {
    target_group_arn = "${aws_lb_target_group.nlb_target_group.arn}"
    type             = "forward"
  }
}

resource "aws_autoscaling_attachment" "svc_asg_nlb-dmz" {
  provider               = "aws.child"
  depends_on             = ["aws_autoscaling_group.asg_dmz_f5"]
  autoscaling_group_name = "${aws_autoscaling_group.asg_dmz_f5.id}"
  alb_target_group_arn   = "${aws_lb_target_group.nlb_target_group.arn}"
}
