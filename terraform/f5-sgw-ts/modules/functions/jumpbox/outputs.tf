output "jumphost_ip" {
  description = "Public IP address of Jumpbox"
  value       = module.jumphost.public_ip
}

output "juiceshop_ips" {
  value = aws_eip.juiceshop
}

output "grafana_ips" {
  value = aws_eip.grafana
}