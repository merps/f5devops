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

  name = "${var.project}_prod"
  cidr = "10.3.0.0/16"

  azs              = ["ap-southeast-2a", "ap-southeast-2b", "ap-southeast-2c"]
  private_subnets  = ["10.3.1.0/24", "10.3.2.0/24", "10.3.3.0/24"]
  public_subnets   = ["10.3.0.0/26", "10.3.0.64/26", "10.3.0.128/26"]
  database_subnets = ["10.3.4.0/24", "10.3.5.0/24", "10.3.6.0/24"]

  enable_nat_gateway = true
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
## Tableau stanza
############################################################
resource "aws_network_acl" "nacl_prod" {
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

resource "aws_security_group" "sg_tableau" {
  provider    = "aws.child"
  name        = "sg_${var.project}-${var.environment}_tableau"
  description = "Tableau Security group"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
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
    "Name" = "sg_${var.project}-${var.environment}_tableau"
  }
}

resource "aws_launch_configuration" "lc_tableau" {
  provider                    = "aws.child"
  name                        = "lc_${var.project}-${var.environment}_tableau"
  image_id                    = "ami-80f322e2"
  instance_type               = "m4.4xlarge"
  iam_instance_profile        = "iam_${var.project}-${var.environment}_tableau"
  key_name                    = "kp_${var.project}-${var.environment}_windows"
  security_groups             = ["${aws_security_group.sg_tableau.id}"]
  enable_monitoring           = false
  ebs_optimized               = false
  associate_public_ip_address = true

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 150
    delete_on_termination = true
  }
}

resource "aws_autoscaling_group" "asg_tableau" {
  provider                  = "aws.child"
  desired_capacity          = 2
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "${aws_launch_configuration.lc_tableau.name}"
  max_size                  = 3
  min_size                  = 2
  name                      = "asg_${var.project}-${var.environment}_tableau"
  vpc_zone_identifier       = ["${module.vpc.public_subnets}"]

  tag {
    key                 = "Environment"
    value               = "${var.environment}"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "${var.environment}_tableau"
    propagate_at_launch = true
  }
}

resource "aws_alb" "dmz-intranet" {
  provider        = "aws.child"
  name            = "elb-${var.project}-${var.environment}-intranet"
  internal        = true
  security_groups = ["${aws_security_group.sg_tableau.id}"]
  subnets         = ["${module.vpc.public_subnets}"]

  enable_deletion_protection = false

  tags {}
}
