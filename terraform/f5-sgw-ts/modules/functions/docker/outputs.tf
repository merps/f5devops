output "docker_private_ip" {
  description = "List of IDs of intra subnets"
  value       = module.dockerhost.private_ip
}