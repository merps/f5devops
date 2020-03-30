output "mgmt_public_ips" {
  description = "BIG-IQ Management Public IP Addresses"
  value       = module.bigip.mgmt_public_ips
}

output "mgmt_public_dns" {
  description = "BIG-IQ Management Public FQDN's"
  value       = module.bigip.mgmt_public_dns
}

output "mgmt_addresses" {
  description = "BIG-IQ Managemment Private IP's"
  value       = module.bigip.mgmt_addresses
}
output "private_addresses" {
  description = "BIG-IQ Private VS IP's"
  value       = module.bigip.private_addresses
}

output "bigiq_mgmt_port" {
  description = "BIG-IQ Management Port"
  value       = module.bigip.mgmt_port
}

output "bigiq_password" {
  description = "BIG-IQ management password"
  value       = random_password.password.result
}
