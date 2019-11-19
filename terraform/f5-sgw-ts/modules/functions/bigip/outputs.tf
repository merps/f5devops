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