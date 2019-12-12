output "jumphost_ip" {
  description = "Public IP address of Jumpbox"
  value       = module.jumphost.public_ip
}

output "juiceshop_ips" {
  description = "Juiceshop EIP IP Addresses"
  value       = aws_eip.juiceshop
}

output "grafana_ips" {
  description = "Grafana EIP IP Addresses"
  value       = aws_eip.grafana
}