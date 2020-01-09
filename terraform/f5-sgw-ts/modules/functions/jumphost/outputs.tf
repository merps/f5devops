output "jumphost_public_ip" {
  description = "Public IP address of Jumpbox"
  value       = module.jumphost.public_ip
}

output "jumphost_private_ip" {
  description = "Private IP address of Jumpbox"
  value       = module.jumphost.private_ip
}