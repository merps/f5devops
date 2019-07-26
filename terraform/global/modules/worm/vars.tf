variable "child-account-bucket" {
  description = "The name of the AWS account you are logging for / the client's account name"
}

variable "child-account-id" {
  description = "The AWS account ID you are logging for / the client's AWS account ID"
}

variable "child-project" {
  description = "The client project/product you are logging for"
}

variable "child-account-env" {
  description = "The environment eg. dev, nonprod, prod"
}

variable "child-account-region" {
  description = "The region of environment eg. dev, nonprod, prod"
}
