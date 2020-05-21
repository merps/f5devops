

data "aws_ami" "latest-ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}


module "jumphost" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 2.0"

  name           = format("%s-demo-jumphost-%s", var.prefix, var.random.hex)
  instance_count = length(var.azs)

  ami                         = data.aws_ami.latest-ubuntu.id
  associate_public_ip_address = true
  instance_type               = "t2.xlarge"
  key_name                    = var.keyname
  monitoring                  = false
  vpc_security_group_ids      = [module.jumphost_sg.this_security_group_id]
  subnet_ids                  = var.public_subnets

  # build user_data file from template
  user_data = templatefile("${path.module}/files/userdata.tmpl", {})

  # this box needs to know the ip address of the bigip and the juicebox host
  # it also needs to know the bigip username and password to use

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.prefix
  }
}

#
# Create a security group for the jumphost
#
module "jumphost_sg" {
  source = "terraform-aws-modules/security-group/aws"

  name        = format("%s-jumphost-%s", var.prefix, var.random.hex)
  description = "Security group for BIG-IP Demo"
  vpc_id      = var.vpcid

  ingress_cidr_blocks = [var.allowed_mgmt_cidr]
  ingress_rules       = ["https-443-tcp", "ssh-tcp"]
  ingress_with_cidr_blocks = [
    {
      from_port   = 3300
      to_port     = 3300
      protocol    = "tcp"
      description = "Juiceshop ports"
      cidr_blocks = var.allowed_mgmt_cidr
    },
    {
      from_port   = 3000
      to_port     = 3000
      protocol    = "tcp"
      description = "Juiceshop ports"
      cidr_blocks = var.allowed_mgmt_cidr
    },
  ]

  # Allow ec2 instances outbound Internet connectivity
  egress_cidr_blocks = ["0.0.0.0/0"]
  egress_rules       = ["all-all"]
}
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
        appserver_host_ip      = module.jumphost.private_ip[count.index] # the ip address that the jumphost has on the public subnet
        bigip_dns_server       = "8.8.8.8"
      }
    )

    destination = "~/inventory.yml"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.keyfile)
      host        = module.jumphost.public_ip[count.index]
    }
  }
}

#
# Hack for remote exec of provisioning
#
resource "null_resource" "ansible" {
  depends_on = [null_resource.hostvars]
  count      = length(var.azs)
  provisioner "file" {
    source      = var.keyfile
    destination = "~/${var.keyname}.pem"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.keyfile)
      host        = module.jumphost.public_ip[count.index]
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
      host        = module.jumphost.public_ip[count.index]
    }
  }
}

data "aws_network_interface" "bar" {
  count = length(var.public_nic_ids)
  id    = var.public_nic_ids[count.index]
}

resource "aws_eip" "juiceshop" {
  depends_on                = [null_resource.hostvars]
  count                     = length(var.azs)
  vpc                       = true
  network_interface         = data.aws_network_interface.bar[count.index].id
  associate_with_private_ip = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 1)
  tags = {
    Name = format("%s-juiceshop-eip-%s%s", var.prefix, var.random.hex, count.index)
  }
}

resource "aws_eip" "grafana" {
  depends_on                = [null_resource.hostvars]
  count                     = length(var.azs)
  vpc                       = true
  network_interface         = data.aws_network_interface.bar[count.index].id
  associate_with_private_ip = element(flatten(data.aws_network_interface.bar[count.index].private_ips), 2)
  tags = {
    Name = format("%s-grafana-eip-%s%s", var.prefix, var.random.hex, count.index)
  }
}