terraform {
  backend "s3" {}
}

provider "aws" {
  alias   = "child"
  profile = "${var.parent-profile}"
  region  = "${var.aws-region}"

  assume_role {
    role_arn = "arn:aws:iam::495525536654:role/DdevopsCrossAccountAdministrators"
  }
}

provider "aws" {
  alias   = "logging"
  profile = "${var.parent-profile}"
  region  = "${var.aws-region}"

  assume_role {
    role_arn = "arn:aws:iam::729494319877:role/DdevopsCrossAccountAdministrators"
  }
}

module "vpc" {
  source = "../global/modules/vpc"

  providers = {
    aws = "aws.child"
  }

  name = "${var.project}"
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

module "worm" {
  source = "../global/modules/worm"

  providers = {
    aws = "aws.logging"
  }

  child-account-bucket = "${var.project}-${var.environment}"
  child-project        = "${var.project}"
  child-account-id     = "${var.child-account-id}"
  child-account-env    = "${var.environment}"
}

/*
module "cloudtrail" {
  source = "../global/modules/cloudtrail"

  providers = {
    aws = "aws.child"
  }

  child-account-id   = "${var.child-account-id}"
  child-profile      = "${var.child-profile}"
  logging-account-id = "${var.logging-account-id}"
}

resource "aws_eip" "ngw_eip" {
  vpc = true
}

resource "aws_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.prod.id}"

  tags {
    Name        = "igw_${var.project}-${var.environment}"
    Environment = "${var.environment}"
    Project     = "${var.project}"
    UniqueOwner = "${var.customer}"
  }
}

resource "aws_nat_gateway" "ngw" {
  allocation_id = "${aws_eip.ngw_eip.id}"
  subnet_id     = "${aws_subnet.public_subnet_a.id}"

  depends_on = [
    "aws_internet_gateway.igw",
  ]

  tags {
    Name        = "nat_${var.project}-${var.environment}"
    Environment = "${var.environment}"
    Project     = "${var.project}"
    UniqueOwner = "${var.customer}"
  }
}

resource "aws_alb" "dmz-internet" {
  name            = "elb-${var.project}-dmz-internet"
  internal        = false
  security_groups = []
  subnets         = ["subnet-0363034a", "subnet-42be4e1a", "subnet-52f88f35"]

  enable_deletion_protection = false

  tags {}
}

resource "aws_alb" "dmz-intranet" {
  name            = "elb-${var.project}-dmz-intranet"
  internal        = true
  security_groups = []
  subnets         = ["subnet-00234349", "subnet-38acdb5f", "subnet-a843b2f0"]

  enable_deletion_protection = false

  tags {}
}

resource "aws_autoscaling_group" "asg_dmz_f5" {
  desired_capacity          = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "lc_rr-idas_dmz_f5"
  max_size                  = 1
  min_size                  = 1
  name                      = "asg_rr-idas_dmz_f5"
  vpc_zone_identifier       = ["subnet-0363034a", "subnet-52f88f35", "subnet-42be4e1a"]

  tag {
    key                 = "Environment"
    value               = "production"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "dmz-f5"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "asg_r-server" {
  desired_capacity          = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "lc_rr-idas_prod_r-server"
  max_size                  = 1
  min_size                  = 1
  name                      = "asg_rr-idas_prod_r-server"
  vpc_zone_identifier       = ["subnet-38acdb5f", "subnet-00234349", "subnet-a843b2f0"]

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "r-server-prod"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "asg_tableau" {
  desired_capacity          = 3
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "lc_rr-idas_prod_tableau"
  max_size                  = 3
  min_size                  = 3
  name                      = "asg_rr-idas_prod_tableau"
  vpc_zone_identifier       = ["subnet-38acdb5f", "subnet-00234349", "subnet-a843b2f0"]

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "tableau-prod"
    propagate_at_launch = true
  }
}

resource "aws_launch_configuration" "lc_dmz_f5" {
  name                 = "lc_rr-idas_dmz_f5"
  image_id             = "ami-c68077a4"
  instance_type        = "t2.medium"
  iam_instance_profile = "iam_rr-idas-prod_linux"
  key_name             = "kp_prod_linux"
  security_groups      = ["sg-2f76cc56"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 42
    delete_on_termination = true
  }
}

resource "aws_launch_configuration" "lc_r-server" {
  name                 = "lc_rr-idas_prod_r-server"
  image_id             = "ami-2abe7348"
  instance_type        = "m3.medium"
  iam_instance_profile = "iam_rr-idas-prod_linux"
  key_name             = "kp_prod_linux"
  security_groups      = ["sg-fa398183"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 8
    delete_on_termination = true
  }
}

resource "aws_launch_configuration" "lc_tableau" {
  name                 = "lc_rr-idas_prod_tableau"
  image_id             = "ami-4b985a29"
  instance_type        = "m5.2xlarge"
  iam_instance_profile = "iam_rr-idas_prod-tableau"
  key_name             = "kp_prod_windows"
  security_groups      = ["sg-1546fe6c"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 100
    delete_on_termination = true
  }
}

resource "aws_autoscaling_group" "asg_rr-idas_dmz_f5" {
  desired_capacity          = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "lc_rr-idas_dmz_f5"
  max_size                  = 1
  min_size                  = 1
  name                      = "asg_rr-idas_dmz_f5"
  vpc_zone_identifier       = ["subnet-0363034a", "subnet-52f88f35", "subnet-42be4e1a"]

  tag {
    key                 = "Environment"
    value               = "production"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "dmz-f5"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "asg_rr-idas_prod_r-server" {
  desired_capacity          = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "lc_rr-idas_prod_r-server"
  max_size                  = 1
  min_size                  = 1
  name                      = "asg_rr-idas_prod_r-server"
  vpc_zone_identifier       = ["subnet-38acdb5f", "subnet-00234349", "subnet-a843b2f0"]

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "r-server-prod"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "asg_rr-idas_prod_tableau" {
  desired_capacity          = 3
  health_check_grace_period = 300
  health_check_type         = "EC2"
  launch_configuration      = "lc_rr-idas_prod_tableau"
  max_size                  = 3
  min_size                  = 3
  name                      = "asg_rr-idas_prod_tableau"
  vpc_zone_identifier       = ["subnet-38acdb5f", "subnet-00234349", "subnet-a843b2f0"]

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }

  tag {
    key                 = "Name"
    value               = "tableau-prod"
    propagate_at_launch = true
  }
}

resource "aws_launch_configuration" "lc_rr-idas_dmz_f5" {
  name                 = "lc_rr-idas_dmz_f5"
  image_id             = "ami-c68077a4"
  instance_type        = "t2.medium"
  iam_instance_profile = "iam_rr-idas-prod_linux"
  key_name             = "kp_prod_linux"
  security_groups      = ["sg-2f76cc56"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 42
    delete_on_termination = true
  }
}

resource "aws_launch_configuration" "lc_rr-idas_prod_r-server" {
  name                 = "lc_rr-idas_prod_r-server"
  image_id             = "ami-2abe7348"
  instance_type        = "m3.medium"
  iam_instance_profile = "iam_rr-idas-prod_linux"
  key_name             = "kp_prod_linux"
  security_groups      = ["sg-fa398183"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 8
    delete_on_termination = true
  }
}

resource "aws_launch_configuration" "lc_rr-idas_prod_tableau" {
  name                 = "lc_rr-idas_prod_tableau"
  image_id             = "ami-4b985a29"
  instance_type        = "m5.2xlarge"
  iam_instance_profile = "iam_rr-idas_prod-tableau"
  key_name             = "kp_prod_windows"
  security_groups      = ["sg-1546fe6c"]
  enable_monitoring    = false
  ebs_optimized        = false

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 100
    delete_on_termination = true
  }
}

resource "aws_network_acl" "acl-7df7ec1a" {
  vpc_id     = "vpc-c31c63a4"
  subnet_ids = ["subnet-84e837dc", "subnet-7f517c18", "subnet-d6f5aa9f"]

  ingress {
    from_port  = 0
    to_port    = 0
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
  }

  egress {
    from_port  = 0
    to_port    = 0
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
  }

  tags {}
}

resource "aws_network_acl" "nacl_rr-idas_prod" {
  vpc_id     = "vpc-0506606bcd37fe012"
  subnet_ids = ["subnet-001c5c3ecb36d5c72", "subnet-0070cb119a948eaa0", "subnet-0102bc253f303ebdc", "subnet-0e605ede9fe109285", "subnet-08124be04ab7faa95", "subnet-07ae7671e0ec8331c", "subnet-093880a65acdd5897", "subnet-07d7eae1f112cc99a", "subnet-0f2779d8f46de2592"]

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
    "Name" = "nacl_rr-idas_prod"
  }
}
*/

