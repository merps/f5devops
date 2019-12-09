# Demo deployment of BIG-IPs using Terraform
Demo deployment of F5 BIG-IP in AWS using Terraform

This is a refactor of https://github.com/mjmenger/terraform-aws-bigip-setup to present a more modular approach of deployement.  As per source, below, all aspects are applicable - the intention is to provide TS to SumoLogic for the deployment of a secure gateway solution within AWS.

an authentication token must be generated and recorded as documented below in order to access the modules required by this demo
https://www.terraform.io/docs/commands/cli-config.html

Initially this demo is run from the local workstation.

# Using your workstation
- install Terraform https://learn.hashicorp.com/terraform/getting-started/install.html
- install inpsec https://www.inspec.io/downloads/
- install locust https://docs.locust.io/en/stable/installation.html
- install jq https://stedolan.github.io/jq/download/

# Required Resource
This example creates the following resources inside of AWS.  Please ensure your IAM user or IAM Role has privileges to create these objects.

**Note:** This example requires 4 Elastic IPs, please ensure your EIP limit on your account can accommodate this (information on ElasticIP limits can be found at https://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#limits_ec2)
 - AWS VPC
 - AWS Route Tables
 - AWS Nat Gateways
 - AWS Elastic IPs
 - AWS EC2 Instances
 - AWS Subnets
 - AWS Security Groups
 
 **Note:** In order to use this demo your AWS account must be subscribed to the F5 AMI and its associated terms and conditions. If your account is not subscribed, the first time ```terraform apply``` is run you will receive an error similar to the following:

```
 Error: Error launching source instance: OptInRequired: In order to use this AWS Marketplace product you need to accept terms and subscribe. To do so please 
visit https://aws.amazon.com/marketplace/pp?sku=XXXXXXXXXXXXXXXXXXXXXXXX
```
The url embedded within the error message will load the appropriate location in order to subscribe the AWS account to the F5 AMI.

After subscribing, re-run the ```terraform apply``` and the error should not occur again.

# Access Credentials
```bash
#starting from within the clone of this repository
vi secrets.tfvars
```
enter the following in the *secrets.tfvars* file
```hcl-terraform
cidr           = "<VPC CIDR Block>"
region         = "<AWS Deployment Region>"
azs            = ["<primary az>", "<secondary az>"]
secops-profile = "<AWS_PROFILE>"
customer       = "<Cusotomer Tage Prefix>"
ec2_key_name   = "<EC2 Keypair>"
ec2_key_file   = "<EC2 Private Key Absolution /path/to/filename.pem>"
environment    = "<Environment - Tag>"
project        = "<Project - Tag>"
```
save the file and quit vi

# Setup 

Due to the modulistion of the demo structure this demo is created from ```secure``` path, after the repo has been cloned; 
```hcl
# Enter secure demo path
cd secure/
# initialize Terraform
terraform init
# Plan terraform to validate deployment
terraform plan --var-file=/path/to/secrets.tfvars
# build the BIG-IPS and the underpinning infrastructure
terraform apply --var-file=/path/to/secrets.tfvars
```
Depending upon how you intend to use the environment you may need to wait after Terraform is complete. The configuration of the  BIG-IPs is completed asynchoronously. If you need the BIG-IPs to be fully configured before proceeding, the following Inspec tests validate the connectivity of the BIG-IP and the availability of the management API end point.

```
# check the status of the BIG-IPs
# these steps can also be performed using ./runtests.sh
#
terraform output --json > inspec/bigip-ready/files/terraform.json
inspec exec inspec/bigip-ready
```
once the tests all pass the BIG-IPs are ready

If terraform returns an error, rerun ```terraform apply --var-file=/path/to/secrets.tfvars```.

# Log into the BIG-IP
```
#
# find the connection info for the BIG-IP
# these steps can also be performed by using ./findthehosts.sh
#
export BIGIPHOST0=`terraform output --json | jq -r '.bigip_mgmt_public_ips.value[0]'`
export BIGIPMGMTPORT=`terraform output --json | jq -r '.bigip_mgmt_port.value'`
export BIGIPPASSWORD=`terraform output --json | jq -r '.bigip_password.value'`
export JUMPHOSTIP=`terraform output --json | jq -r '.jumphost_ip.value[0]'`
echo connect at https://$BIGIPHOST0:$BIGIPMGMTPORT with $BIGIPPASSWORD
echo connect to jumphost at with
echo ssh -i "<THE AWS KEY YOU IDENTIFIED ABOVE>" ubuntu@$JUMPHOSTIP
```
connect to the BIGIP at https://<bigip_mgmt_public_ips>:<bigip_mgmt_port>
login as user:admin and password: <bigip_password>

# Teardown
When you are done using the demo environment you will need to decommission it
```hcl
terraform destroy --var-file=/path/to/secret.tfvars
```

as a final step check that terraform doesn't think there's anything remaining
```hcl
terraform show
```
this should return a blank line

# Todo
* adjust subnets and ranges to remove hardcoding for dynamic generation (smaller cidr for inspections)
* template var passes between deployment and modules
* AWS SSM integration for keystore/passwords
* flow log addition/creation for CIS Foundations
* AWS Security HUB(?)

# Credits
* Mark Menhjar - Terraform AWS BIG-IP Setup - <https://github.com/mjmenger/terraform-aws-bigip-setup>
* Daniel Edgar - Ansible Uber Demo - <https://github.com/>

