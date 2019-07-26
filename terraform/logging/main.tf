terraform {
  backend "s3" {
  }
}

data "terraform_remote_state" "remote_state" {
  backend = "s3"
  config {
  }
}

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

module "iam" {
    source = "../global/modules/iam"
    providers = {
        aws = "aws.parent"
    }

    child-account-name = "${var.project}-${var.environment}-${var.customer}"
    child-account-id = "${var.child-account-id}"
}

module "cloudtrail" {
    source = "../global/modules/cloudtrail"
    providers = {
        aws = "aws.logging"
    }

    child-account-name = "${var.project}-${var.environment}-${var.customer}"
    child-account-id = "${var.child-account-id}"
    logging-account-id = "${var.logging-account-id}"
}

module "config" {
    source = "../global/modules/config"
    providers = {
        aws = "aws.child"
    }

    config_s3_bucket = "${var.project}-$(var.environment}-${var.customer}-config"
}
