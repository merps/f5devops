terraform {
  backend "s3" {}
}

data "terraform_remote_state" "remote_state" {
  backend = "s3"
  config  = {}
}

provider "aws" {
  alias   = "parent"
  region  = "${var.aws-region}"
  profile = "${var.parent-profile}"

  assume_role {
    role_arn = "arn:aws:iam::${var.child-account-id}:role/DdevopsCrossAccountAdmins"
  }
}

provider "aws" {
  alias   = "child"
  region  = "${var.aws-region}"
  profile = "${var.parent-profile}"

  assume_role {
    role_arn = "arn:aws:iam::${var.child-account-id}:role/DdevopsCrossAccountAdmins"
  }
}

provider "aws" {
  alias   = "logging"
  region  = "${var.aws-region}"
  profile = "${var.parent-profile}"

  assume_role {
    role_arn = "arn:aws:iam::${var.logging-account-id}:role/DdevopsCrossAccountAdmins"
  }
}

module "iam" {
  source = "../global/modules/iam"

  providers = {
    aws = "aws.parent"
  }

  child-account-name = "${var.project}-${var.environment}-${var.customer}"
  child-account-id   = "${var.child-account-id}"
}
/*
module "worm" {
  source = "../global/modules/worm"

  providers = {
    aws = "aws.logging"
  }

  child-account-bucket = "${var.project}-${var.environment}"
  child-account-cust   = "${var.customer}"
  child-account-id     = "${var.child-account-id}"
  child-account-env    = "${var.environment}"
  logging-account-id   = "${var.logging-account-id}"
  aws-region           = "${var.aws-region}"
}

module "cloudtrail" {
  source = "../global/modules/cloudtrail"

  providers = {
    aws = "aws.logging"
  }

  child-account-name = "${var.project}-${var.environment}-${var.customer}"
  child-account-id   = "${var.child-account-id}"
  logging-account-id = "${var.logging-account-id}"
}

module "config" {
  source = "../global/modules/config"

  providers = {
    aws = "aws.child"
  }

  config_s3_bucket   = "${var.project}-$(var.environment}-${var.customer}-config"
  child-account-name = "${var.project}-${var.environment}-${var.customer}"
  child-account-id   = "${var.child-account-id}"
  logging-account-id = "${var.logging-account-id}"
}
*/
module "openvpn" {
  source = "../global/services/openvpn"
  name   = "openVPN"

  # VPC Inputs
  vpc_id            = "${var.vpc_id}"
  vpc_cidr          = "${var.vpc_cidr}"
  public_subnet_ids = "${var.public_subnet_ids}"

  # EC2 Inputs
  key_name      = "${var.key_name}"
  private_key   = "${var.private_key}"
  ami           = "${var.ami}"
  instance_type = "${var.instance_type}"

  # ELB Inputs
  cert_arn = "${var.cert_arn}"

  # DNS Inputs
  domain_name   = "${var.public_domain_name}"
  route_zone_id = "${var.route_zone_id}"

  # OpenVPN Inputs
  openvpn_user       = "${var.openvpn_user}"
  openvpn_admin_user = "${var.openvpn_admin_user}" # Note: Don't choose "admin" username. Looks like it's already reserved.
  openvpn_admin_pw   = "${var.openvpn_admin_pw}"
}
