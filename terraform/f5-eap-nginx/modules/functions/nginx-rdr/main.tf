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

resource null_resource "ansible_rdr" {
  depends_on = [
    "module.nginx-rdr"
  ]

  provisioner "local-exec" {
    command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ec2-user --private-key '${var.keyfile}' -i '${module.nginx-rdr.public_ip},' ansible/main.yml"
  }
}

module "nginx-rdr" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 2.0"

  name           = format("%s-demo-nginx-rdr-%s", var.prefix, var.random.hex)
  instance_count = 1

  ami                         = data.aws_ami.latest-ubuntu.id
  associate_public_ip_address = true
  instance_type               = "t2.xlarge"
  key_name                    = var.keyname
  monitoring                  = false
  vpc_security_group_ids      = [module.nginx-rdr_sg.this_security_group_id]
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
module "nginx-rdr_sg" {
  source = "terraform-aws-modules/security-group/aws"

  name        = format("%s-jumphost-%s", var.prefix, var.random.hex)
  description = "Security group for EAP-RDR PoC"
  vpc_id      = var.vpcid

  ingress_cidr_blocks = [var.allowed_mgmt_cidr]
  ingress_rules       = ["https-443-tcp", "ssh-tcp"]

  # Allow ec2 instances outbound Internet connectivity
  egress_cidr_blocks = ["0.0.0.0/0"]
  egress_rules       = ["all-all"]
}