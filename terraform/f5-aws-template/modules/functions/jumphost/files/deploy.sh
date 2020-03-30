#!/bin/bash
## This is install & configure ansible
cd /home/ubuntu
git clone https://github.com/merps/ansible-uber-demo.git
cd ansible-uber-demo
cp /home/ubuntu/inventory.yml /home/ubuntu/ansible-uber-demo/ansible/inventory.yml
ansible-galaxy install -r ansible/requirements.yml
ansible-playbook ansible/playbooks/site.yml
