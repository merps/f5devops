/* # Terraform remote state store bucket name
backend_s3 = "terraform-data-rr-idas-prod"

# Account IDs
aws_account_shared = "556201001071" # Volley Shared / Central

aws_account_nonprod = "502889103111" # Volley Nonprod

aws_account_prod = "564117060686" # Volley Prod

aws_account_logging = "351725868221" # Strut WORM

customer_name = "rr-idas"

# Project-specific tags
name = "rr-idas"

project_name = "RR-IDAS"

unique_owner = "rr-idas"
*/
variable "parent-profile" {
  description = "AWS Parent Profile to configure for."
}

variable "parent-account-id" {
  description = "AWS Parent Number to configure for."
}

variable "child-profile" {
  description = "Account name to configure Cloudtrail for."
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

variable "static_eips" {
  default = {
    "0" = "eipalloc-0ef2fcf22cf8088ba"
    "1" = "eipalloc-0ba8e5292d169d29a"
    "2" = "eipalloc-08a3fcd57b5339ce3"
  }
}
