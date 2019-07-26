variable "vpc" {
  description = "VPC ID for application of configuration."
}

variable "parent-profile" {
  description = "AWS Parent Profile to configure for."
}

variable "parent-account-id" {
  description = "AWS Parent Number to configure for."
}

variable "child-account-name" {
  description = "AWS Sub-account Name to configure for."
}

variable "child-account-bucket" {
  description = "The name of the AWS account you are logging for / the client's account name"
}

variable "child-account-id" {
  description = "The AWS account ID you are logging for / the client's AWS account ID"
}

variable "child-profile" {
  description = "The client project/product you are logging for"
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

variable "logging-account-id" {
  description = "Log id to configure Cloudtrail for."
}
