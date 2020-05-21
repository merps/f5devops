#
# Set minimum Terraform version and Terraform Cloud backend
#
terraform {
  required_version = ">= 0.12"
}
/*
# Create a random id
*/
resource "random_id" "id" {
  byte_length = 2
}
/*
# Create VPC as per requirements
*/
module "vpc" {
  source = "../modules/services/network"

  providers = {
    aws = aws.secops
  }

  prefix = "${var.project}-${var.environment}"
  cidr   = var.cidr
  azs    = var.azs
  env    = var.environment
  random = random_id.id

}

# Create Docker host as per requirements
module "docker" {
  source = "../modules/functions/docker"

  providers = {
    aws = aws.secops
  }

  prefix          = "${var.project}-${var.environment}"
  cidr            = var.cidr
  azs             = var.azs
  env             = var.environment
  vpcid           = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnets
  random          = random_id.id
  keyname         = var.ec2_key_name
  keyfile         = var.ec2_key_file
}

# Create Jump host as per requirements
module "jumphost" {
  source = "../modules/functions/jumphost"

  providers = {
    aws = aws.secops
  }

  prefix            = "${var.project}-${var.environment}"
  region            = var.region
  cidr              = var.cidr
  azs               = var.azs
  env               = var.environment
  vpcid             = module.vpc.vpc_id
  public_subnets    = module.vpc.public_subnets
  docker_private_ip = module.docker.docker_private_ip
  random            = random_id.id
  keyname           = var.ec2_key_name
  keyfile           = var.ec2_key_file

}

module "nginx-rdr" {
  source = "../modules/functions/nginx-rdr"

  providers = {
    aws = aws.secops
  }

  prefix            = "${var.project}-${var.environment}"
  region            = var.region
  cidr              = var.cidr
  azs               = var.azs
  env               = var.environment
  vpcid             = module.vpc.vpc_id
  public_subnets    = module.vpc.public_subnets
  random            = random_id.id
  keyname           = var.ec2_key_name
  keyfile           = var.ec2_key_file

}