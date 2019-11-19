variable "ami_id" {}
variable "subnet_id" {}
variable "instance_type" {}
variable "key_name" {}

variable "security_groups" {
  type = "list"
}

variable "tag_name" {}
variable "tag_environment_name" {}
variable "tag_project_name" {}
variable "tag_unique_owner" {}

resource "aws_instance" "nix_bastion_ec2" {
  ami           = "${var.ami_id}"
  count         = 1
  subnet_id     = "${var.subnet_id}"
  instance_type = "${var.instance_type}"
  key_name      = "${var.key_name}"

  tags {
    Name        = "${var.tag_environment_name}-nix_bastion-${var.tag_name}"
    Environment = "${var.tag_environment_name}"
    Project     = "${var.tag_project_name}"
    UniqueOwner = "${var.tag_unique_owner}"
  }

  vpc_security_group_ids = ["${var.security_groups}"]

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 8
    delete_on_termination = true
  }
}
