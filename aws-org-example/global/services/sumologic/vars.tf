variable "parent-profile" {
  description = "AWS Parent Profile to configure for."
}

variable "parent-account-id" {
  description = "AWS Parent Number to configure for."
}

variable "child-account-id" {
  description = "AWS Sub-account Number to configure for."
}

variable "logging-account-id" {
  description = "AWS Logging Number to configure for."
}

variable "aws-region" {
  description = "AWS Region to configure for."
}

variable "aws-profile" {
  description = "AWS Sub-account Profile to configure for."
}

variable "customer" {
  description = "Customer Short name AWS deployment is for."
}

variable "environment" {
  description = "Customer Environment short name for deployment."
}

variable "project" {
  description = "Customer Project short name for deployment."
}

variable "vpc" {
  description = "VPC ID for application of configuration."
}

variable "profile" {}

variable "subnet_a_private" {}

variable "subnet_b_private" {}

variable "subnet_c_private" {}

variable "lambda_exec_security_group" {}

variable "stage" {}

variable "region" {}

variable "sumo_endpoint" {}