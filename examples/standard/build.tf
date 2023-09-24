module "start_stop" {
  source = "../../"


  name     = "vmstartstop"
  location = local.location
  tags     = local.tags

  email_receivers = [
    {
      name          = "Alerts"
      email_address = "info@cyber.scot"
    }
  ]

  create_law_linked_app_insights = true
  create_new_law                 = true

  scheduled_start_logic_app_enabled                    = true
  scheduled_start_logic_app_evaluation_frequency       = "Week"
  scheduled_start_logic_app_evaluation_interval_number = 1
  scheduled_start_schedules = [
    {
      days    = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
      hours   = ["08"]
      minutes = ["00"]
    }
  ]
  scheduled_start_resource_group_scopes = [
    module.rg.rg_id
  ]

  scheduled_stop_logic_app_enabled                    = true
  scheduled_stop_logic_app_evaluation_frequency       = "Week"
  scheduled_stop_logic_app_evaluation_interval_number = 1
  scheduled_stop_schedules = [
    {
      days    = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
      hours   = ["18"]
      minutes = ["00"]
    }
  ]
  scheduled_stop_resource_group_scopes = [
    module.rg.rg_id
  ]
}

module "rg" {
  source = "cyber-scot/rg/azurerm"

  name     = "rg-${var.short}-${var.loc}-${var.env}-01"
  location = local.location
  tags     = local.tags
}

module "network" {
  source = "cyber-scot/network/azurerm"

  rg_name  = module.rg.rg_name
  location = module.rg.rg_location
  tags     = module.rg.rg_tags

  vnet_name          = "vnet-${var.short}-${var.loc}-${var.env}-01"
  vnet_location      = module.rg.rg_location
  vnet_address_space = ["10.0.0.0/16"]

  subnets = {
    "sn1-${module.network.vnet_name}" = {
      prefix            = "10.0.0.0/24",
      service_endpoints = ["Microsoft.Storage"]
    }
  }
}

module "nsg" {
  source = "cyber-scot/nsg/azurerm"

  rg_name  = module.rg.rg_name
  location = module.rg.rg_location
  tags     = module.rg.rg_tags

  nsg_name              = "nsg-${var.short}-${var.loc}-${var.env}-01"
  associate_with_subnet = true
  subnet_id             = element(values(module.network.subnets_ids), 0)
  custom_nsg_rules = {
    "AllowVnetInbound" = {
      priority                   = 100
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "VirtualNetwork"
      destination_address_prefix = "VirtualNetwork"
    }
  }
}

module "windows_11_vms" {
  source = "cyber-scot/windows-virtual-machine/azurerm"
  vms = [
    {
      rg_name        = module.rg.rg_name
      location       = module.rg.rg_location
      tags           = module.rg.rg_tags
      name           = "vm-${var.short}-${var.loc}-${var.env}-01"
      subnet_id      = element(values(module.network.subnets_ids), 0)
      admin_username = "Local${title(var.short)}${title(var.env)}Admin"
      admin_password = data.azurerm_key_vault_secret.mgmt_admin_pwd.value
      vm_size        = "Standard_B2ms"
      timezone       = "UTC"
      vm_os_simple   = "Windows11"
      os_disk = {
        disk_size_gb = 256
      }
    },
  ]
}
