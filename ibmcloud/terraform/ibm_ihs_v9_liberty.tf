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

##############################################################
# Define the ibm provider 
##############################################################
#define the ibm provider
provider "ibm" {
  version = "~> 0.5"
}

provider "camc" {
  version = "~> 0.1"
}

provider "random" {
  version = "~> 1.0"
}

##############################################################
# Reference public key in Devices>Manage>SSH Keys in SL console) 
##############################################################
data "ibm_compute_ssh_key" "ibm_pm_public_key" {
  label = "${var.ibm_pm_public_ssh_key_name}"
  most_recent = "true"
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
    UBUNTU_16_64 = "root"
    REDHAT_7_64 = "root"
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
#Variable : IHSLiberty9Node01-image
variable "IHSLiberty9Node01-image" {
  type = "string"
  description = "Operating system image id / template that should be used when creating the virtual image"
  default = "REDHAT_7_64"
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


##### ungrouped variables #####
##### domain name #####
variable "runtime_domain" {
  description = "domain name"
  default = "cam.ibm.com"
}


#########################################################
##### Resource : IHSLiberty9Node01
#########################################################


#Parameter : IHSLiberty9Node01_datacenter
variable "IHSLiberty9Node01_datacenter" {
  type = "string"
  description = "IBMCloud datacenter where infrastructure resources will be deployed"
  default = "dal05"
}


#Parameter : IHSLiberty9Node01_private_network_only
variable "IHSLiberty9Node01_private_network_only" {
  type = "string"
  description = "Provision the virtual machine with only private IP"
  default = "false"
}


#Parameter : IHSLiberty9Node01_number_of_cores
variable "IHSLiberty9Node01_number_of_cores" {
  type = "string"
  description = "Number of CPU cores, which is required to be a positive Integer"
  default = "2"
}


#Parameter : IHSLiberty9Node01_memory
variable "IHSLiberty9Node01_memory" {
  type = "string"
  description = "Amount of Memory (MBs), which is required to be one or more times of 1024"
  default = "2048"
}


#Parameter : IHSLiberty9Node01_network_speed
variable "IHSLiberty9Node01_network_speed" {
  type = "string"
  description = "Bandwidth of network communication applied to the virtual machine"
  default = "10"
}


#Parameter : IHSLiberty9Node01_hourly_billing
variable "IHSLiberty9Node01_hourly_billing" {
  type = "string"
  description = "Billing cycle: hourly billed or monthly billed"
  default = "true"
}


#Parameter : IHSLiberty9Node01_dedicated_acct_host_only
variable "IHSLiberty9Node01_dedicated_acct_host_only" {
  type = "string"
  description = "Shared or dedicated host, where dedicated host usually means higher performance and cost"
  default = "false"
}


#Parameter : IHSLiberty9Node01_local_disk
variable "IHSLiberty9Node01_local_disk" {
  type = "string"
  description = "User local disk or SAN disk"
  default = "false"
}

variable "IHSLiberty9Node01_root_disk_size" {
  type = "string"
  description = "Root Disk Size - IHSLiberty9Node01"
  default = "25"
}

resource "ibm_compute_vm_instance" "IHSLiberty9Node01" {
  hostname = "${var.IHSLiberty9Node01-name}"
  os_reference_code = "${var.IHSLiberty9Node01-image}"
  domain = "${var.runtime_domain}"
  datacenter = "${var.IHSLiberty9Node01_datacenter}"
  network_speed = "${var.IHSLiberty9Node01_network_speed}"
  hourly_billing = "${var.IHSLiberty9Node01_hourly_billing}"
  private_network_only = "${var.IHSLiberty9Node01_private_network_only}"
  cores = "${var.IHSLiberty9Node01_number_of_cores}"
  memory = "${var.IHSLiberty9Node01_memory}"
  disks = ["${var.IHSLiberty9Node01_root_disk_size}"]
  dedicated_acct_host_only = "${var.IHSLiberty9Node01_dedicated_acct_host_only}"
  local_disk = "${var.IHSLiberty9Node01_local_disk}"
  ssh_key_ids = ["${data.ibm_compute_ssh_key.ibm_pm_public_key.id}"]
  # Specify the ssh connection
  connection {
    user = "${var.IHSLiberty9Node01-os_admin_user == "" ? lookup(var.default_os_admin_user, var.IHSLiberty9Node01-image) : var.IHSLiberty9Node01-os_admin_user}"
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

}

#########################################################
##### Resource : IHSLiberty9Node01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "IHSLiberty9Node01_chef_bootstrap_comp" {
  depends_on = ["camc_vaultitem.VaultItem","ibm_compute_vm_instance.IHSLiberty9Node01"]
  name = "IHSLiberty9Node01_chef_bootstrap_comp"
  camc_endpoint = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "os_admin_user": "${var.IHSLiberty9Node01-os_admin_user == "default"? lookup(var.default_os_admin_user, var.IHSLiberty9Node01-image) : var.IHSLiberty9Node01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.IHSLiberty9Node01-mgmt-network-public == "false" ? ibm_compute_vm_instance.IHSLiberty9Node01.ipv4_address_private : ibm_compute_vm_instance.IHSLiberty9Node01.ipv4_address}",
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
  "os_admin_user": "${var.IHSLiberty9Node01-os_admin_user == "default"? lookup(var.default_os_admin_user, var.IHSLiberty9Node01-image) : var.IHSLiberty9Node01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.IHSLiberty9Node01-mgmt-network-public == "false" ? ibm_compute_vm_instance.IHSLiberty9Node01.ipv4_address_private : ibm_compute_vm_instance.IHSLiberty9Node01.ipv4_address}",
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
  value = "Private : ${ibm_compute_vm_instance.IHSLiberty9Node01.ipv4_address_private} & Public : ${ibm_compute_vm_instance.IHSLiberty9Node01.ipv4_address}"
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

