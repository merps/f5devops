# Network Information
output "vpc" {
  description = "AWS VPC ID for the created VPC"
  value       = module.vpc.vpc_id
}

# BIG-IP Information
output "public_nic_ids" {
  value = module.bigip.public_nic_ids
}

output "bigip_mgmt_public_ips" {
  value = module.bigip.mgmt_public_ips
}
output "bigip_mgmt_port" {
  value = module.bigip.bigip_mgmt_port
}

output "mgmt_public_dns" {
  value = module.bigip.mgmt_public_dns
}

output "bigip_password" {
  description = "BIG-IP management password"
  value       = module.bigip.bigip_password
}

# Jumpbox information
output "jumphost_ip" {
  description = "ip address of jump host"
  value       = module.jumphost.jumphost_ip
}

#Ansible Module
output "juiceshop_ip" {
  value = module.ansible.juiceshop_ips[*].public_ip
}

output "grafana_ip" {
  value = module.ansible.grafana_ips[*].public_ip
}

# Instance Information
output "ec2_key_name" {
  description = "the key used to communication with ec2 instances"
  value       = var.ec2_key_name
}

