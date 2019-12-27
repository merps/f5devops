data "aws_network_interface" "bar" {
  count = length(var.public_nic_ids)
  id    = var.public_nic_ids[count.index]
}
/*
#
# Create and place the inventory.yml file for the ansible demo
#
resource "null_resource" "hostvars" {
  count = length(var.azs)
  provisioner "file" {
    content = templatefile(
      "${path.module}/files/hostvars_template.yml",
      {
        bigip_host_ip          = join(",", element(var.bigip_mgmt_addr, count.index)) #bigip_host_ip          = module.bigip.mgmt_public_ips[count.index]  the ip address that the bigip has on the management subnet
        bigip_host_dns         = var.bigip_mgmt_dns[count.index]                      # the DNS name of the bigip on the public subnet
        bigip_domain           = "${var.region}.compute.internal"
        bigip_username         = "admin"
        bigip_password         = var.bigip_password
        ec2_key_name           = var.keyname
        ec2_username           = "ubuntu"
        log_pool               = cidrhost(cidrsubnet(var.cidr, 8, count.index + var.internal_subnet_offset), 250)
        bigip_external_self_ip = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 0) # the ip address that the bigip has on the public subnet
        bigip_internal_self_ip = join(",", element(var.bigip_private_add, count.index))                       # the ip address that the bigip has on the private subnet
        juiceshop_virtual_ip   = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 1)
        grafana_virtual_ip     = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 2)
        appserver_gateway_ip   = cidrhost(cidrsubnet(var.cidr, 8, count.index + var.internal_subnet_offset), 1)
        appserver_guest_ip     = var.docker_private_ip[count.index]
        appserver_host_ip      = var.jumphost_ip.private_ip[count.index] # the ip address that the jumphost has on the public subnet
        bigip_dns_server       = "8.8.8.8"
      }
    )

    destination = "~/inventory.yml"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.keyfile)
      host        = var.jumphost_ip.public_ip[count.index]
    }
  }
}
*/
#
# Hack for remote exec of provisioning
#
resource "null_resource" "ansible" {
  /* depends_on = [null_resource.hostvars] */
  count      = length(var.azs)
  provisioner "file" {
    source      = var.keyfile
    destination = "~/${var.keyname}.pem"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.keyfile)
      host        = var.jumphost_ip.public_ip[count.index]
    }
  }

  provisioner "remote-exec" {
    inline = [
      "chmod 600 ~/${var.keyname}.pem",
      "git clone https://github.com/merps/ansible-uber-demo.git",
      "cp ~/inventory.yml ~/ansible-uber-demo/ansible/inventory.yml",
      "cd ~/ansible-uber-demo/",
      "ansible-galaxy install -r ansible/requirements.yml",
      "sudo ansible-playbook ansible/playbooks/site.yml"
    ]

    connection {
      type        = "ssh"
      timeout     = "10m"
      user        = "ubuntu"
      private_key = file(var.keyfile)
      host        = var.jumphost_ip.public_ip[count.index]
    }
  }
}

resource "aws_eip" "juiceshop" {
  /* depends_on                = [null_resource.hostvars] */
  count                     = length(var.azs)
  vpc                       = true
  network_interface         = data.aws_network_interface.bar[count.index].id
  associate_with_private_ip = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 1)
  tags = {
    Name = format("%s-juiceshop-eip-%s%s", var.prefix, var.random.hex, count.index)
  }
}

resource "aws_eip" "grafana" {
  /* depends_on                = [null_resource.hostvars] */
  count                     = length(var.azs)
  vpc                       = true
  network_interface         = data.aws_network_interface.bar[count.index].id
  associate_with_private_ip = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 2)
  tags = {
    Name = format("%s-grafana-eip-%s%s", var.prefix, var.random.hex, count.index)
  }
}
