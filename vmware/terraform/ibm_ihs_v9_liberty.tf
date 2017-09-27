# =================================================================
# Licensed Materials - Property of IBM
# 5737-E67
# @ Copyright IBM Corporation 2016, 2017 All Rights Reserved
# US Government Users Restricted Rights - Use, duplication or disclosure
# restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================

# This is a terraform generated template generated from ibm_ihs_v9_liberty

##############################################################
# Keys - CAMC (public/private) & optional User Key (public)
##############################################################
variable "user_public_ssh_key" {
  type        = "string"
  description = "User defined public SSH key used to connect to the virtual machine. The format must be in openSSH."
  default     = "None"
}

variable "ibm_pm_public_ssh_key" {
  description = "Public CAMC SSH key value which is used to connect to a guest, used on VMware only."
}

variable "ibm_pm_private_ssh_key" {
  description = "Private CAMC SSH key (base64 encoded) used to connect to the virtual guest."
}

variable "allow_unverified_ssl" {
  description = "Communication with vsphere server with self signed certificate"
  default     = "true"
}

##############################################################
# Define the vsphere provider
##############################################################
provider "vsphere" {
  allow_unverified_ssl = "${var.allow_unverified_ssl}"
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

##### Environment variables #####
#Variable : ibm_im_repo
variable "ibm_im_repo" {
  type        = "string"
  description = "IBM Software  Installation Manager Repository URL (https://<hostname/IP>:<port>/IMRepo) "
}

#Variable : ibm_im_repo_password
variable "ibm_im_repo_password" {
  type        = "string"
  description = "IBM Software  Installation Manager Repository Password"
}

#Variable : ibm_im_repo_user
variable "ibm_im_repo_user" {
  type        = "string"
  description = "IBM Software  Installation Manager Repository username"
  default     = "repouser"
}

#Variable : ibm_pm_access_token
variable "ibm_pm_access_token" {
  type        = "string"
  description = "IBM Pattern Manager Access Token"
}

#Variable : ibm_pm_service
variable "ibm_pm_service" {
  type        = "string"
  description = "IBM Pattern Manager Service"
}

#Variable : ibm_sw_repo
variable "ibm_sw_repo" {
  type        = "string"
  description = "IBM Software Repo Root (https://<hostname>:<port>)"
}

#Variable : ibm_sw_repo_password
variable "ibm_sw_repo_password" {
  type        = "string"
  description = "IBM Software Repo Password"
}

#Variable : ibm_sw_repo_user
variable "ibm_sw_repo_user" {
  type        = "string"
  description = "IBM Software Repo Username"
  default     = "repouser"
}

##### IHSLiberty9Node01 variables #####
#Variable : IHSLiberty9Node01-image
variable "IHSLiberty9Node01-image" {
  type        = "string"
  description = "Operating system image id / template that should be used when creating the virtual image"
}

#Variable : IHSLiberty9Node01-name
variable "IHSLiberty9Node01-name" {
  type        = "string"
  description = "Short hostname of virtual machine"
}

#Variable : IHSLiberty9Node01-os_admin_user
variable "IHSLiberty9Node01-os_admin_user" {
  type        = "string"
  description = "Name of the admin user account in the virtual machine that will be accessed via SSH"
}

#Variable : IHSLiberty9Node01_ihs_admin_server_enabled
variable "IHSLiberty9Node01_ihs_admin_server_enabled" {
  type        = "string"
  description = "IBM HTTP Server Admin Server Enable(true/false)"
  default     = "false"
}

#Variable : IHSLiberty9Node01_ihs_install_dir
variable "IHSLiberty9Node01_ihs_install_dir" {
  type        = "string"
  description = "The directory to install IBM HTTP Server"
  default     = "/opt/IBM/HTTPServer"
}

#Variable : IHSLiberty9Node01_ihs_install_mode
variable "IHSLiberty9Node01_ihs_install_mode" {
  type        = "string"
  description = "The mode of installation for IBM HTTP Server"
  default     = "nonAdmin"
}

#Variable : IHSLiberty9Node01_ihs_java_legacy
variable "IHSLiberty9Node01_ihs_java_legacy" {
  type        = "string"
  description = "The Java version to be used with IBM HTTP Server version 8.5.5"
  default     = "java8"
}

#Variable : IHSLiberty9Node01_ihs_java_version
variable "IHSLiberty9Node01_ihs_java_version" {
  type        = "string"
  description = "The Java version to be used with IBM HTTP Server"
  default     = "8.0.4.70"
}

#Variable : IHSLiberty9Node01_ihs_os_users_ihs_gid
variable "IHSLiberty9Node01_ihs_os_users_ihs_gid" {
  type        = "string"
  description = "The group name for the IBM HTTP Server user"
  default     = "ihsgrp"
}

#Variable : IHSLiberty9Node01_ihs_os_users_ihs_name
variable "IHSLiberty9Node01_ihs_os_users_ihs_name" {
  type        = "string"
  description = "The username for IBM HTTP Server"
  default     = "ihssrv"
}

#Variable : IHSLiberty9Node01_ihs_os_users_ihs_shell
variable "IHSLiberty9Node01_ihs_os_users_ihs_shell" {
  type        = "string"
  description = "Location of the IBM HTTP Server operating system user shell"
  default     = "/sbin/nologin"
}

#Variable : IHSLiberty9Node01_ihs_plugin_enabled
variable "IHSLiberty9Node01_ihs_plugin_enabled" {
  type        = "string"
  description = "IBM HTTP Server Plugin Enabled"
  default     = "true"
}

#Variable : IHSLiberty9Node01_ihs_plugin_install_dir
variable "IHSLiberty9Node01_ihs_plugin_install_dir" {
  type        = "string"
  description = "IBM HTTP Server Plugin Installation Direcrtory"
  default     = "/opt/IBM/WebSphere/Plugins"
}

#Variable : IHSLiberty9Node01_ihs_plugin_was_webserver_name
variable "IHSLiberty9Node01_ihs_plugin_was_webserver_name" {
  type        = "string"
  description = "IBM HTTP Server Plugin Hostname, normally the FQDN"
  default     = "webserver1"
}

#Variable : IHSLiberty9Node01_ihs_port
variable "IHSLiberty9Node01_ihs_port" {
  type        = "string"
  description = "The IBM HTTP Server default port for HTTP requests"
  default     = "8080"
}

#Variable : IHSLiberty9Node01_ihs_version
variable "IHSLiberty9Node01_ihs_version" {
  type        = "string"
  description = "The version of IBM HTTP Server to install"
  default     = "9.0.0.4"
}

#########################################################
##### Resource : IHSLiberty9Node01
#########################################################

variable "IHSLiberty9Node01-os_password" {
  type        = "string"
  description = "Operating System Password for the Operating System User to access virtual machine"
}

variable "IHSLiberty9Node01_folder" {
  description = "Target vSphere folder for virtual machine"
}

variable "IHSLiberty9Node01_datacenter" {
  description = "Target vSphere datacenter for virtual machine creation"
}

variable "IHSLiberty9Node01_number_of_vcpu" {
  description = "Number of virtual CPU for the virtual machine, which is required to be a positive Integer"
  default     = "2"
}

variable "IHSLiberty9Node01_memory" {
  description = "Memory assigned to the virtual machine in megabytes. This value is required to be an increment of 1024"
  default     = "2048"
}

variable "IHSLiberty9Node01_cluster" {
  description = "Target vSphere cluster to host the virtual machine"
}

variable "IHSLiberty9Node01_dns_suffixes" {
  type        = "list"
  description = "Name resolution suffixes for the virtual network adapter"
}

variable "IHSLiberty9Node01_dns_servers" {
  type        = "list"
  description = "DNS servers for the virtual network adapter"
}

variable "IHSLiberty9Node01_network_interface_label" {
  description = "vSphere port group or network label for virtual machine's vNIC"
}

variable "IHSLiberty9Node01_ipv4_gateway" {
  description = "IPv4 gateway for vNIC configuration"
}

variable "IHSLiberty9Node01_ipv4_address" {
  description = "IPv4 address for vNIC configuration"
}

variable "IHSLiberty9Node01_ipv4_prefix_length" {
  description = "IPv4 prefix length for vNIC configuration. The value must be a number between 8 and 32"
}

variable "IHSLiberty9Node01_root_disk_datastore" {
  description = "Data store or storage cluster name for target virtual machine's disks"
}

variable "IHSLiberty9Node01_root_disk_type" {
  type        = "string"
  description = "Type of template disk volume"
  default     = "eager_zeroed"
}

variable "IHSLiberty9Node01_root_disk_controller_type" {
  type        = "string"
  description = "Type of template disk controller"
  default     = "scsi"
}

variable "IHSLiberty9Node01_root_disk_keep_on_remove" {
  type        = "string"
  description = "Delete template disk volume when the virtual machine is deleted"
  default     = "false"
}

# vsphere vm
resource "vsphere_virtual_machine" "IHSLiberty9Node01" {
  name         = "${var.IHSLiberty9Node01-name}"
  folder       = "${var.IHSLiberty9Node01_folder}"
  datacenter   = "${var.IHSLiberty9Node01_datacenter}"
  vcpu         = "${var.IHSLiberty9Node01_number_of_vcpu}"
  memory       = "${var.IHSLiberty9Node01_memory}"
  cluster      = "${var.IHSLiberty9Node01_cluster}"
  dns_suffixes = "${var.IHSLiberty9Node01_dns_suffixes}"
  dns_servers  = "${var.IHSLiberty9Node01_dns_servers}"

  network_interface {
    label              = "${var.IHSLiberty9Node01_network_interface_label}"
    ipv4_gateway       = "${var.IHSLiberty9Node01_ipv4_gateway}"
    ipv4_address       = "${var.IHSLiberty9Node01_ipv4_address}"
    ipv4_prefix_length = "${var.IHSLiberty9Node01_ipv4_prefix_length}"
  }

  disk {
    type            = "${var.IHSLiberty9Node01_root_disk_type}"
    template        = "${var.IHSLiberty9Node01-image}"
    datastore       = "${var.IHSLiberty9Node01_root_disk_datastore}"
    keep_on_remove  = "${var.IHSLiberty9Node01_root_disk_keep_on_remove}"
    controller_type = "${var.IHSLiberty9Node01_root_disk_controller_type}"
  }

  # Specify the connection
  connection {
    type     = "ssh"
    user     = "${var.IHSLiberty9Node01-os_admin_user}"
    password = "${var.IHSLiberty9Node01-os_password}"
  }

  provisioner "file" {
    destination = "IHSLiberty9Node01_add_ssh_key.sh"

    content = <<EOF
##############################################################
# Licensed Materials - Property of IBM
#
# For use by authorized subscribers only.
#
# Refer to Service Description and SLA available here:
# http://www-03.ibm.com/software/sla/sladb.nsf/sla/saas
#
# D0021ZX IBM Cloud Automation Library, Enterprise Middleware
# © Copyright IBM Corp. 2017
##############################################################
#!/bin/bash

if (( $# != 3 )); then
echo "usage: arg 1 is user, arg 2 is public key, arg3 is CAMC Public Key"
exit -1
fi

userid="$1"
ssh_key="$2"
camc_ssh_key="$3"

user_home=$(eval echo "~$userid")
user_auth_key_file=$user_home/.ssh/authorized_keys
echo "$user_auth_key_file"
if ! [ -f $user_auth_key_file ]; then
echo "$user_auth_key_file does not exist on this system, creating."
mkdir $user_home/.ssh
chmod 600 $user_home/.ssh
echo "" > $user_home/.ssh/authorized_keys
chmod 600 $user_home/.ssh/authorized_keys
else
echo "user_home : $user_home"
fi

if [[ $ssh_key = 'None' ]]; then
echo "skipping user key add, 'None' specified"
else
echo "$user_auth_key_file"
echo "$ssh_key" >> "$user_auth_key_file"
if [ $? -ne 0 ]; then
echo "failed to add to $user_auth_key_file"
exit -1
else
echo "updated $user_auth_key_file"
fi
fi

echo "$camc_ssh_key" >> "$user_auth_key_file"
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
      "sudo bash -c 'chmod +x IHSLiberty9Node01_add_ssh_key.sh'",
      "sudo bash -c './IHSLiberty9Node01_add_ssh_key.sh  \"${var.IHSLiberty9Node01-os_admin_user}\" \"${var.user_public_ssh_key}\" \"${var.ibm_pm_public_ssh_key}\">> IHSLiberty9Node01_add_ssh_key.log 2>&1'",
    ]
  }
}

#########################################################
##### Resource : IHSLiberty9Node01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "IHSLiberty9Node01_chef_bootstrap_comp" {
  depends_on      = ["camc_vaultitem.VaultItem", "vsphere_virtual_machine.IHSLiberty9Node01"]
  name            = "IHSLiberty9Node01_chef_bootstrap_comp"
  camc_endpoint   = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "os_admin_user": "${var.IHSLiberty9Node01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.IHSLiberty9Node01.network_interface.0.ipv4_address}",
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
  depends_on      = ["camc_bootstrap.IHSLiberty9Node01_chef_bootstrap_comp"]
  name            = "IHSLiberty9Node01_ihs-liberty-nonadmin"
  camc_endpoint   = "${var.ibm_pm_service}/v1/software_deployment/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "os_admin_user": "${var.IHSLiberty9Node01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.IHSLiberty9Node01.network_interface.0.ipv4_address}",
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
  camc_endpoint   = "${var.ibm_pm_service}/v1/vault_item/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

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
  value = "VM IP Address : ${vsphere_virtual_machine.IHSLiberty9Node01.network_interface.0.ipv4_address}"
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
