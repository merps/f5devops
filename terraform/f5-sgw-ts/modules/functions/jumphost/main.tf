

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