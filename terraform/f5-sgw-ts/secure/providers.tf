provider "aws" {
  alias   = "secops"
  profile = "${var.secops-profile}"
  region  = "${var.aws-region}"
}

provider "aws" {
  alias   = "logging"
  profile = "${var.logging-profile}"
  region  = "${var.aws-region}"
}