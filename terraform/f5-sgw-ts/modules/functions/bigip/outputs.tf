output "public_nic_ids" {
  value = module.bigip.public_nic_ids
}

output "mgmt_addresses" {
  value = module.bigip.mgmt_addresses
}

output "mgmt_public_dns" {
  value = module.bigip.mgmt_public_dns
}

output "private_addresses" {
  value = module.bigip.private_addresses
}

output "bigip_mgmt_port" {
  value = module.bigip.mgmt_port
}

output "bigip_password" {
  description = "BIG-IP management password"
  value       = random_password.password.result
}
