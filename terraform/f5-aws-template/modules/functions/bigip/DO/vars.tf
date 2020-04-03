variable "mgmt_public_ips" {
  description = "BIG-IP Management Public IP Addresses"
  type = string
}

variable "mgmt_public_dns" {
  description = "BIG-IP Management Public FQDN's"
  type = string
}

variable "mgmt_addresses" {
  description = "BIG-IP Managemment Private IP's"
  type = string
}
variable "private_addresses" {
  description = "BIG-IP Private VS IP's"
  type = string
}

variable "bigip_mgmt_port" {
  description = "BIG-IP Management Port"
  type = string
}

variable "bigip_password" {
  description = "BIG-IP management password"
  type = string
}
