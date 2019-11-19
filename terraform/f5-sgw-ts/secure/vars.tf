variable "cidr" {
  description = "VPC CIDR for Inspection gateway."
}

variable "parent-account-id" {
  description = "AWS Parent Number to configure for."
}

variable "secops-profile" {
  description = "Account name to configure Environment for."
}

variable "child-account-id" {
  description = "AWS child-account Number to configure for."
}

variable "logging-profile" {
  description = "AWS Logging Profile to configure for."
}

variable "logging-account-id" {
  description = "AWS Logging Number to configure for."
}

variable "aws-region" {
  description = "AWS Region to configure for."
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

variable "admin-role" {
  description = "Cross Account Admin Role for deployment."
}

variable "nlb_listener_protocol" {
  description = "protocol"
  default     = "TCP"
}

variable "nlb_svc_port" {
  description = "Listener port?"
  default     = "8443"
}

variable "nlb_svc_priority" {
  description = "priority"
  default     = "1"
}

variable "target_group_path" {
  description = "tg path"
  default     = "/"
}

variable "target_group_port" {
  description = "tg port"
  default     = "8443"
}

variable "nlb_svc_path" {
  description = "Listener path?"
  default     = "/"
}
