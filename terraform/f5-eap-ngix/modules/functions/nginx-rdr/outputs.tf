output "jumphost_ip" {
  description = "Public IP address of NGNIX-RDR"
  value       = module.nginx-rdr.public_ip
}