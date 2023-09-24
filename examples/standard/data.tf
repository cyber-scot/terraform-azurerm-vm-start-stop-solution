data "azurerm_client_config" "current" {}

### Management data

data "azurerm_resource_group" "mgmt_rg" {
  name = "rg-${var.short}-${var.loc}-${var.env}-mgmt"
}

data "azurerm_key_vault" "mgmt_kv" {
  name                = "kv-${var.short}-${var.loc}-${var.env}-mgmt-01"
  resource_group_name = data.azurerm_resource_group.mgmt_rg.name
}

data "azurerm_key_vault_secret" "mgmt_admin_pwd" {
  key_vault_id = data.azurerm_key_vault.mgmt_kv.id
  name         = "Local${title(var.short)}Admin${title(var.env)}Pwd"
}
