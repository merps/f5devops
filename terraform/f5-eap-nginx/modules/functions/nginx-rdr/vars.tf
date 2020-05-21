variable "cidr" {
  description = "aws Deployment VPC CIDR Block"
}

variable "prefix" {
  description = "aws deployment prefix"
}

variable "public_subnets" {
  description = "AWS Deployment Public Subnets"
}

variable "azs" {
  description = "AWS Deployment region Availability Zones"
}

variable "env" {
  description = "AWS deployment environment"
}

variable "random" {
  description = "Random ID for naming"
}

variable "keyname" {
  description = "EC2 Keyname"
}

variable "keyfile" {
  description = "EC2 local PEM File"
}

variable "vpcid" {
  description = "AWS VPC IP of deployment"
}

variable "region" {
  description = "AWS Region of deployment"
}

variable "allowed_mgmt_cidr" {
  default = "0.0.0.0/0"
}
variable "allowed_app_cidr" {
  default = "0.0.0.0/0"
}

variable "internal_subnet_offset" {
  default = 20
}