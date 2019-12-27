output "juiceshop_ips" {
  description = "Juiceshop EIP IP Addresses"
  value       = aws_eip.juiceshop
}

output "grafana_ips" {
  description = "Grafana EIP IP Addresses"
  value       = aws_eip.grafana
}
