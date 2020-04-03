## https://support.f5.com/csp/article/K23449665
provider "bigip" {
  address = var.mgmt_public_dns
  username = "admin"
  password = "default"
}

data "template_file" "init" {
  template = file("${path.module}/templates/do-declaration.tpl")
  vars = {
    bigip_hostname = var.mgmt_public_dns
    bigip_dns_server = "8.8.8.8"
    bigip_external_self_ip = var.mgmt_public_ips
    #bigip_internal_self_ip = var.private_addresses
  }
}

resource "bigip_do" "bigip" {
  do_json = data.template_file.init.rendered
  tenant_name = "sample_test"
 }