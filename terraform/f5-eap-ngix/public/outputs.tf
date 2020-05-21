# Network Information
output "vpc" {
  description = "AWS VPC ID for the created VPC"
  value       = module.vpc.vpc_id
}
/*
# Jumpbox information
output "jumphost_ip" {
  description = "ip address of jump host"
  value       = module.jumphost.jumphost_ip
}

output "juiceshop_ip" {
  value = module.jumphost.juiceshop_ips[*].public_ip
}

output "grafana_ip" {
  value = module.jumphost.grafana_ips[*].public_ip
}

# Instance Information
output "ec2_key_name" {
  description = "the key used to communication with ec2 instances"
  value       = var.ec2_key_name
}
*/