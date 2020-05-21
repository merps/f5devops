output "public_nic_ids" {
  description = "BIG-IP Public EIP ID's"
  value       = module.bigip.public_nic_ids
}

output "mgmt_public_ips" {
  description = "BIG-IP Management Public IP Addresses"
  value       = module.bigip.mgmt_public_ips
}

output "mgmt_public_dns" {
  description = "BIG-IP Management Public FQDN's"
  value       = module.bigip.mgmt_public_dns
}

output "mgmt_addresses" {
  description = "BIG-IP Managemment Private IP's"
  value       = module.bigip.mgmt_addresses
}
output "private_addresses" {
  description = "BIG-IP Private VS IP's"
  value       = module.bigip.private_addresses
}

output "bigip_mgmt_port" {
  description = "BIG-IP Management Port"
  value       = module.bigip.mgmt_port
}

output "bigip_password" {
  description = "BIG-IP management password"
  value       = random_password.password.result
}
