output "jumphost_ip" {
  description = "Public IP address of Jumpbox"
  value       = module.jumphost.public_ip
}