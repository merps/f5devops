variable "cidr" {

}

variable "prefix" {

}

variable "public_subnets" {

}

variable "azs" {

}

variable "env" {

}

variable "random" {

}

variable "keyname" {

}

variable "keyfile" {

}
variable "vpcid" {

}

variable "region" {}

variable "allowed_mgmt_cidr" {
  default = "0.0.0.0/0"
}

variable "allowed_app_cidr" {
  default = "0.0.0.0/0"
}

variable "public_nic_ids" {}

variable "internal_subnet_offset" {
  default = 20
}