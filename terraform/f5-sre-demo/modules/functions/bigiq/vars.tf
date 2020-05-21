variable "cidr" {

}

variable "prefix" {

}

variable "private_subnets" {

}

variable "database_subnets" {

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

variable "allowed_mgmt_cidr" {
  default = "0.0.0.0/0"
}

variable "allowed_app_cidr" {
  default = "0.0.0.0/0"
}