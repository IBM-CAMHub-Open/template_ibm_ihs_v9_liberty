# This is a terraform generated template generated from ibm_ihs_v9_liberty

##############################################################
# Keys - CAMC (public/private) & optional User Key (public) 
##############################################################
variable "ibm_pm_public_ssh_key_name" {
  description = "Public CAMC SSH key name used to connect to the virtual guest."
}

variable "ibm_pm_private_ssh_key" {
  description = "Private CAMC SSH key (base64 encoded) used to connect to the virtual guest."
}

variable "user_public_ssh_key" {
  type = "string"
  description = "User defined public SSH key used to connect to the virtual machine. The format must be in openSSH."
  default = "None"
}

variable "aws_ami_owner_id" {
  description = "The AMI Owner ID"
  default = "309956199498"
}

variable "aws_region" {
  description = "The aws region"
  default = "us-east-1"
}

##############################################################
# Define the aws provider 
##############################################################
provider "aws" {
  region = "${var.aws_region}"
  version = "~> 1.2"
}

provider "camc" {
  version = "~> 0.1"
}

provider "random" {
  version = "~> 1.0"
}

data "aws_vpc" "selected_vpc" {
  filter {
    name = "tag:Name"
    values = ["${var.aws_vpc_name}"]
  }
}

#Parameter : aws_vpc_name
variable "aws_vpc_name" {
  description = "The name of the aws vpc"
}

data "aws_security_group" "aws_sg_camc_name_selected" {
  name = "${var.aws_sg_camc_name}"
  vpc_id = "${data.aws_vpc.selected_vpc.id}"
}

#Parameter : aws_sg_camc_name
variable "aws_sg_camc_name" {
  description = "The name of the aws security group for automation content"
}

resource "random_id" "stack_id" {
  byte_length = "16"
}

##############################################################
# Define pattern variables 
##############################################################
##### unique stack name #####
variable "ibm_stack_name" {
  description = "A unique stack name."
}

#### Default OS Admin User Map ####
variable "default_os_admin_user" {
  type        = "map"
  description = "look up os_admin_user using resource image"
  default = {
    ubuntu_images_ubuntu_xenial-16.04_099720109477 = "ubuntu"
    RHEL-7.4_HVM_GA_309956199498                   = "ec2-user"
  }
}

##### Environment variables #####
#Variable : ibm_im_repo
variable "ibm_im_repo" {
  type = "string"
  description = "IBM Software  Installation Manager Repository URL (https://<hostname/IP>:<port>/IMRepo) "
}

#Variable : ibm_im_repo_password
variable "ibm_im_repo_password" {
  type = "string"
  description = "IBM Software  Installation Manager Repository Password"
}

#Variable : ibm_im_repo_user
variable "ibm_im_repo_user" {
  type = "string"
  description = "IBM Software  Installation Manager Repository username"
  default = "repouser"
}

#Variable : ibm_pm_access_token
variable "ibm_pm_access_token" {
  type = "string"
  description = "IBM Pattern Manager Access Token"
}

#Variable : ibm_pm_service
variable "ibm_pm_service" {
  type = "string"
  description = "IBM Pattern Manager Service"
}

#Variable : ibm_sw_repo
variable "ibm_sw_repo" {
  type = "string"
  description = "IBM Software Repo Root (https://<hostname>:<port>)"
}

#Variable : ibm_sw_repo_password
variable "ibm_sw_repo_password" {
  type = "string"
  description = "IBM Software Repo Password"
}

#Variable : ibm_sw_repo_user
variable "ibm_sw_repo_user" {
  type = "string"
  description = "IBM Software Repo Username"
  default = "repouser"
}


##### IHSLiberty9Node01 variables #####
#Variable : IHSLiberty9Node01-flavor
variable "IHSLiberty9Node01-flavor" {
  type = "string"
  description = "IHSLiberty9Node01 Flavor"
  default = "t2.small"
}

data "aws_ami" "IHSLiberty9Node01_ami" {
  most_recent = true
  filter {
    name = "name"
    values = ["${var.IHSLiberty9Node01-image}*"]
  }
  owners = ["${var.aws_ami_owner_id}"]
}

#Variable : IHSLiberty9Node01-image
variable "IHSLiberty9Node01-image" {
  type = "string"
  description = "Operating system image id / template that should be used when creating the virtual image"
  default = "RHEL-7.4_HVM_GA"
}

#Variable : IHSLiberty9Node01-mgmt-network-public
variable "IHSLiberty9Node01-mgmt-network-public" {
  type = "string"
  description = "Expose and use public IP of virtual machine for internal communication"
  default = "true"
}

#Variable : IHSLiberty9Node01-name
variable "IHSLiberty9Node01-name" {
  type = "string"
  description = "Short hostname of virtual machine"
}

#Variable : IHSLiberty9Node01-os_admin_user
variable "IHSLiberty9Node01-os_admin_user" {
  type = "string"
  description = "Name of the admin user account in the virtual machine that will be accessed via SSH"
}

#Variable : IHSLiberty9Node01_ihs_admin_server_enabled
variable "IHSLiberty9Node01_ihs_admin_server_enabled" {
  type = "string"
  description = "IBM HTTP Server Admin Server Enable(true/false)"
  default = "false"
}

#Variable : IHSLiberty9Node01_ihs_install_dir
variable "IHSLiberty9Node01_ihs_install_dir" {
  type = "string"
  description = "The directory to install IBM HTTP Server"
  default = "/opt/IBM/HTTPServer"
}

#Variable : IHSLiberty9Node01_ihs_install_mode
variable "IHSLiberty9Node01_ihs_install_mode" {
  type = "string"
  description = "The mode of installation for IBM HTTP Server"
  default = "nonAdmin"
}

#Variable : IHSLiberty9Node01_ihs_java_legacy
variable "IHSLiberty9Node01_ihs_java_legacy" {
  type = "string"
  description = "The Java version to be used with IBM HTTP Server version 8.5.5"
  default = "java8"
}

#Variable : IHSLiberty9Node01_ihs_java_version
variable "IHSLiberty9Node01_ihs_java_version" {
  type = "string"
  description = "The Java version to be used with IBM HTTP Server"
  default = "8.0.4.70"
}

#Variable : IHSLiberty9Node01_ihs_os_users_ihs_gid
variable "IHSLiberty9Node01_ihs_os_users_ihs_gid" {
  type = "string"
  description = "The group name for the IBM HTTP Server user"
  default = "ihsgrp"
}

#Variable : IHSLiberty9Node01_ihs_os_users_ihs_name
variable "IHSLiberty9Node01_ihs_os_users_ihs_name" {
  type = "string"
  description = "The username for IBM HTTP Server"
  default = "ihssrv"
}

#Variable : IHSLiberty9Node01_ihs_os_users_ihs_shell
variable "IHSLiberty9Node01_ihs_os_users_ihs_shell" {
  type = "string"
  description = "Location of the IBM HTTP Server operating system user shell"
  default = "/sbin/nologin"
}

#Variable : IHSLiberty9Node01_ihs_plugin_enabled
variable "IHSLiberty9Node01_ihs_plugin_enabled" {
  type = "string"
  description = "IBM HTTP Server Plugin Enabled"
  default = "true"
}

#Variable : IHSLiberty9Node01_ihs_plugin_install_dir
variable "IHSLiberty9Node01_ihs_plugin_install_dir" {
  type = "string"
  description = "IBM HTTP Server Plugin Installation Direcrtory"
  default = "/opt/IBM/WebSphere/Plugins"
}

#Variable : IHSLiberty9Node01_ihs_plugin_was_webserver_name
variable "IHSLiberty9Node01_ihs_plugin_was_webserver_name" {
  type = "string"
  description = "IBM HTTP Server Plugin Hostname, normally the FQDN"
  default = "webserver1"
}

#Variable : IHSLiberty9Node01_ihs_port
variable "IHSLiberty9Node01_ihs_port" {
  type = "string"
  description = "The IBM HTTP Server default port for HTTP requests"
  default = "8080"
}

#Variable : IHSLiberty9Node01_ihs_version
variable "IHSLiberty9Node01_ihs_version" {
  type = "string"
  description = "The version of IBM HTTP Server to install"
  default = "9.0.0.4"
}

##### domain name #####
variable "runtime_domain" {
  description = "domain name"
  default = "cam.ibm.com"
}


#########################################################
##### Resource : IHSLiberty9Node01
#########################################################


#Parameter : IHSLiberty9Node01_subnet_name
data "aws_subnet" "IHSLiberty9Node01_selected_subnet" {
  filter {
    name = "tag:Name"
    values = ["${var.IHSLiberty9Node01_subnet_name}"]
  }
}

variable "IHSLiberty9Node01_subnet_name" {
  type = "string"
  description = "AWS Subnet Name"
}


#Parameter : IHSLiberty9Node01_associate_public_ip_address
variable "IHSLiberty9Node01_associate_public_ip_address" {
  type = "string"
  description = "Assign a public IP"
  default = "true"
}


#Parameter : IHSLiberty9Node01_root_block_device_volume_type
variable "IHSLiberty9Node01_root_block_device_volume_type" {
  type = "string"
  description = "AWS Root Block Device Volume Type"
  default = "gp2"
}


#Parameter : IHSLiberty9Node01_root_block_device_volume_size
variable "IHSLiberty9Node01_root_block_device_volume_size" {
  type = "string"
  description = "AWS Root Block Device Volume Size"
  default = "25"
}


#Parameter : IHSLiberty9Node01_root_block_device_delete_on_termination
variable "IHSLiberty9Node01_root_block_device_delete_on_termination" {
  type = "string"
  description = "AWS Root Block Device Delete on Termination"
  default = "true"
}

resource "aws_instance" "IHSLiberty9Node01" {
  ami = "${data.aws_ami.IHSLiberty9Node01_ami.id}"
  instance_type = "${var.IHSLiberty9Node01-flavor}"
  key_name = "${var.ibm_pm_public_ssh_key_name}"
  vpc_security_group_ids = ["${data.aws_security_group.aws_sg_camc_name_selected.id}"]
  subnet_id = "${data.aws_subnet.IHSLiberty9Node01_selected_subnet.id}"
  associate_public_ip_address = "${var.IHSLiberty9Node01_associate_public_ip_address}"
  tags {
    Name = "${var.IHSLiberty9Node01-name}"
  }

  # Specify the ssh connection
  connection {
    user = "${var.IHSLiberty9Node01-os_admin_user == "" ? lookup(var.default_os_admin_user, format("%s_%s", replace(var.IHSLiberty9Node01-image, "/", "_"), var.aws_ami_owner_id)) : var.IHSLiberty9Node01-os_admin_user}"
    private_key = "${base64decode(var.ibm_pm_private_ssh_key)}"
  }

  provisioner "file" {
    destination = "IHSLiberty9Node01_add_ssh_key.sh"
    content     = <<EOF
# =================================================================
# Licensed Materials - Property of IBM
# 5737-E67
# @ Copyright IBM Corporation 2016, 2017 All Rights Reserved
# US Government Users Restricted Rights - Use, duplication or disclosure
# restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================
#!/bin/bash

if (( $# != 2 )); then
    echo "usage: arg 1 is user, arg 2 is public key"
    exit -1
fi

userid=$1
ssh_key=$2

if [[ $ssh_key = 'None' ]]; then
  echo "skipping add, 'None' specified"
  exit 0
fi

user_home=$(eval echo "~$userid")
user_auth_key_file=$user_home/.ssh/authorized_keys
if ! [ -f $user_auth_key_file ]; then
  echo "$user_auth_key_file does not exist on this system"
  exit -1
else
  echo "user_home --> $user_home"
fi

echo $ssh_key >> $user_auth_key_file
if [ $? -ne 0 ]; then
  echo "failed to add to $user_auth_key_file"
  exit -1
else
  echo "updated $user_auth_key_file"
fi

EOF
  }

  # Execute the script remotely
  provisioner "remote-exec" {
    inline = [
      "bash -c 'chmod +x IHSLiberty9Node01_add_ssh_key.sh'",
      "bash -c './IHSLiberty9Node01_add_ssh_key.sh  \"${var.IHSLiberty9Node01-os_admin_user}\" \"${var.user_public_ssh_key}\">> IHSLiberty9Node01_add_ssh_key.log 2>&1'"
    ]
  }

  root_block_device {
    volume_type = "${var.IHSLiberty9Node01_root_block_device_volume_type}"
    volume_size = "${var.IHSLiberty9Node01_root_block_device_volume_size}"
    #iops = "${var.IHSLiberty9Node01_root_block_device_iops}"
    delete_on_termination = "${var.IHSLiberty9Node01_root_block_device_delete_on_termination}"
  }

  user_data = "${data.template_cloudinit_config.IHSLiberty9Node01_init.rendered}"
}
data "template_cloudinit_config" "IHSLiberty9Node01_init"  {
  part {
    content_type = "text/cloud-config"
    content = <<EOF
hostname: ${var.IHSLiberty9Node01-name}
fqdn: ${var.IHSLiberty9Node01-name}.${var.runtime_domain}
manage_etc_hosts: false
EOF
  }
}

#########################################################
##### Resource : IHSLiberty9Node01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "IHSLiberty9Node01_chef_bootstrap_comp" {
  depends_on = ["camc_vaultitem.VaultItem","aws_instance.IHSLiberty9Node01"]
  name = "IHSLiberty9Node01_chef_bootstrap_comp"
  camc_endpoint = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "os_admin_user": "${var.IHSLiberty9Node01-os_admin_user == "default"? lookup(var.default_os_admin_user, format("%s_%s", replace(var.IHSLiberty9Node01-image, "/", "_"), var.aws_ami_owner_id)) : var.IHSLiberty9Node01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.IHSLiberty9Node01-mgmt-network-public == "false" ? aws_instance.IHSLiberty9Node01.private_ip : aws_instance.IHSLiberty9Node01.public_ip}",
  "node_name": "${var.IHSLiberty9Node01-name}",
  "node_attributes": {
    "ibm_internal": {
      "stack_id": "${random_id.stack_id.hex}",
      "stack_name": "${var.ibm_stack_name}",
      "vault": {
        "item": "secrets",
        "name": "${random_id.stack_id.hex}"
      }
    }
  }
}
EOT
}


#########################################################
##### Resource : IHSLiberty9Node01_ihs-liberty-nonadmin
#########################################################

resource "camc_softwaredeploy" "IHSLiberty9Node01_ihs-liberty-nonadmin" {
  depends_on = ["camc_bootstrap.IHSLiberty9Node01_chef_bootstrap_comp"]
  name = "IHSLiberty9Node01_ihs-liberty-nonadmin"
  camc_endpoint = "${var.ibm_pm_service}/v1/software_deployment/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "os_admin_user": "${var.IHSLiberty9Node01-os_admin_user == "default"? lookup(var.default_os_admin_user, format("%s_%s", replace(var.IHSLiberty9Node01-image, "/", "_"), var.aws_ami_owner_id)) : var.IHSLiberty9Node01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.IHSLiberty9Node01-mgmt-network-public == "false" ? aws_instance.IHSLiberty9Node01.private_ip : aws_instance.IHSLiberty9Node01.public_ip}",
  "node_name": "${var.IHSLiberty9Node01-name}",
  "runlist": "role[ihs-liberty-nonadmin]",
  "node_attributes": {
    "ibm": {
      "im_repo": "${var.ibm_im_repo}",
      "im_repo_user": "${var.ibm_im_repo_user}",
      "sw_repo": "${var.ibm_sw_repo}",
      "sw_repo_user": "${var.ibm_sw_repo_user}"
    },
    "ibm_internal": {
      "roles": "[ihs-liberty-nonadmin]"
    },
    "ihs": {
      "admin_server": {
        "enabled": "${var.IHSLiberty9Node01_ihs_admin_server_enabled}"
      },
      "install_dir": "${var.IHSLiberty9Node01_ihs_install_dir}",
      "install_mode": "${var.IHSLiberty9Node01_ihs_install_mode}",
      "java": {
        "legacy": "${var.IHSLiberty9Node01_ihs_java_legacy}",
        "version": "${var.IHSLiberty9Node01_ihs_java_version}"
      },
      "os_users": {
        "ihs": {
          "gid": "${var.IHSLiberty9Node01_ihs_os_users_ihs_gid}",
          "name": "${var.IHSLiberty9Node01_ihs_os_users_ihs_name}",
          "shell": "${var.IHSLiberty9Node01_ihs_os_users_ihs_shell}"
        }
      },
      "plugin": {
        "enabled": "${var.IHSLiberty9Node01_ihs_plugin_enabled}",
        "install_dir": "${var.IHSLiberty9Node01_ihs_plugin_install_dir}",
        "was_webserver_name": "${var.IHSLiberty9Node01_ihs_plugin_was_webserver_name}"
      },
      "port": "${var.IHSLiberty9Node01_ihs_port}",
      "version": "${var.IHSLiberty9Node01_ihs_version}"
    }
  },
  "vault_content": {
    "item": "secrets",
    "values": {
      "ibm": {
        "im_repo_password": "${var.ibm_im_repo_password}",
        "sw_repo_password": "${var.ibm_sw_repo_password}"
      }
    },
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}


#########################################################
##### Resource : VaultItem
#########################################################

resource "camc_vaultitem" "VaultItem" {
  camc_endpoint = "${var.ibm_pm_service}/v1/vault_item/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "vault_content": {
    "item": "secrets",
    "values": {},
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}

output "IHSLiberty9Node01_ip" {
  value = "Private : ${aws_instance.IHSLiberty9Node01.private_ip} & Public : ${aws_instance.IHSLiberty9Node01.public_ip}"
}

output "IHSLiberty9Node01_name" {
  value = "${var.IHSLiberty9Node01-name}"
}

output "IHSLiberty9Node01_roles" {
  value = "ihs-liberty-nonadmin"
}

output "stack_id" {
  value = "${random_id.stack_id.hex}"
}

