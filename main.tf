data "azurerm_client_config" "current" {}

locals {
  hidden_link_tags = {
    "hidden-link:${azurerm_resource_group.this.id}/providers/Microsoft.Insights/components/${azurerm_resource_group.this.name}" = "Resource"
  }
  combined_hidden_link_tags = merge(var.tags, local.hidden_link_tags)

  solution_tags = {
    SolutionName = "StartStopV2"
  }

  solution_merged_tags = merge(var.tags, local.solution_tags)
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${var.name}"
  location = var.location
  tags     = var.tags
}

resource "azurerm_management_lock" "rg_lock" {
  count      = var.lock_level != null && var.lock_level != "" ? 1 : 0
  name       = "lock-${var.name}"
  scope      = azurerm_resource_group.this.id
  lock_level = var.lock_level
  notes      = "Resource Group '${var.name}' is locked with '${var.lock_level}' level."
}

resource "azurerm_log_analytics_workspace" "law" {
  count                              = var.create_law_linked_app_insights && var.create_new_law ? 1 : 0
  name                               = try(var.law_name, null) != null ? var.law_name : "law-${var.name}"
  location                           = azurerm_resource_group.this.location
  resource_group_name                = azurerm_resource_group.this.name
  allow_resource_only_permissions    = try(var.allow_resource_only_permissions, true)
  local_authentication_disabled      = try(var.local_authentication_disabled, true)
  cmk_for_query_forced               = try(var.cmk_for_query_forced, false, null)
  sku                                = title(try(var.law_sku, null))
  retention_in_days                  = try(var.retention_in_days, null)
  reservation_capacity_in_gb_per_day = var.law_sku == "CapacityReservation" ? var.reservation_capacity_in_gb_per_day : null
  daily_quota_gb                     = title(var.law_sku) == "Free" ? "0.5" : try(var.daily_quota_gb, null)
  internet_ingestion_enabled         = try(var.internet_ingestion_enabled, null)
  internet_query_enabled             = try(var.internet_query_enabled, null)
  tags                               = try(var.tags, null)
}

data "azurerm_log_analytics_workspace" "read_created_law" {
  count               = var.create_law_linked_app_insights && !var.create_new_law ? 1 : 0
  name                = element(azurerm_log_analytics_workspace.law.*.name, 0)
  resource_group_name = azurerm_resource_group.this.name
}

resource "azurerm_application_insights" "app_insights" {
  name                = var.app_insights_name != null ? var.app_insights_name : "appi-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  application_type    = "web"
  disable_ip_masking  = null
  sampling_percentage = 0
  tags                = try(var.tags, null)

  workspace_id = var.create_law_linked_app_insights ? (
    var.create_new_law && var.law_id == null ? azurerm_log_analytics_workspace.law[0].id : var.law_id
  ) : null
}

resource "azurerm_monitor_action_group" "notification_group_ag" {
  name                = var.notification_action_group_name != null ? var.notification_action_group_name : "StartStopV2_VM_Notification"
  resource_group_name = azurerm_resource_group.this.name
  short_name          = var.notification_action_group_short_name != null ? var.notification_action_group_short_name : "StStAlertV2"
  tags                = local.solution_merged_tags
  dynamic "email_receiver" {
    for_each = var.email_receivers
    content {
      email_address = email_receiver.value.email_address
      name          = email_receiver.value.name
    }
  }
}

resource "azurerm_monitor_action_group" "app_insights_ag" {
  name                = var.smart_detection_action_group_name != null ? var.smart_detection_action_group_name : "Application Insights Smart Detection"
  resource_group_name = azurerm_resource_group.this.name
  short_name          = var.smart_detection_action_group_short_name != null ? var.smart_detection_action_group_short_name : "SmartDetect"
  tags                = local.solution_merged_tags
  arm_role_receiver {
    name                    = "Monitoring Contributor"
    role_id                 = "749f88d5-cbae-40b8-bcfc-e573ddc772fa"
    use_common_alert_schema = true
  }
  arm_role_receiver {
    name                    = "Monitoring Reader"
    role_id                 = "43d0d8ad-25c7-4714-9337-8ba259a9fe05"
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "auto_stop_query_alert_rules" {
  description          = "Start/Stop VMs during off-hours : AutoStop azure function has attempted an action"
  evaluation_frequency = "PT5M"
  location             = azurerm_resource_group.this.location
  name                 = var.auto_stop_query_alert_name != null ? var.auto_stop_query_alert_name : "AutoStop_VM_AzFunc"
  resource_group_name  = azurerm_resource_group.this.name
  scopes               = var.auto_stop_query_alert_scopes != [] ? toset([azurerm_application_insights.app_insights.id]) : var.auto_stop_query_alert_scopes
  severity             = 4
  tags                 = local.combined_hidden_link_tags
  window_duration      = "PT5M"
  action {
    action_groups = var.auto_stop_query_action_groups != [] ? toset([azurerm_monitor_action_group.notification_group_ag.id]) : var.auto_stop_query_action_groups
  }
  criteria {
    operator                = "GreaterThan"
    query                   = <<-EOT
      traces
      | where (operation_Name contains "AutoStop")
      | where (message hasprefix "~AutoStop")
      | extend output = substring(message,1)
      | summarize by message, output
      | project output
    EOT
    threshold               = 0
    time_aggregation_method = "Count"
    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "scheduled_query_alert_rules" {
  description          = "Start/Stop VMs during off-hours : Scheduled azure function has attempted an action"
  evaluation_frequency = "PT5M"
  location             = azurerm_resource_group.this.location
  name                 = var.scheduled_start_stop_query_alert_name != null ? var.scheduled_start_stop_query_alert_name : "ScheduledStartStop_AzFunc"
  resource_group_name  = azurerm_resource_group.this.name
  scopes               = var.scheduled_query_alert_scopes != [] ? toset([azurerm_application_insights.app_insights.id]) : var.scheduled_query_alert_scopes
  severity             = 4
  tags                 = local.combined_hidden_link_tags
  window_duration      = "PT5M"
  action {
    action_groups = var.scheduled_query_action_groups != [] ? toset([azurerm_monitor_action_group.notification_group_ag.id]) : var.scheduled_query_action_groups
  }
  criteria {
    operator                = "GreaterThan"
    query                   = <<-EOT
    traces
    | where (operation_Name contains "Scheduled")
    | where (message hasprefix "~Scheduled")
    | extend output = substring(message,1)
    | summarize by message, output
    | project output
  EOT
    threshold               = 0
    time_aggregation_method = "Count"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "sequenced_query_alert_rules" {
  description          = "Start/Stop VMs during off-hours : Sequenced azure function has attempted an action"
  evaluation_frequency = "PT5M"
  location             = azurerm_resource_group.this.location
  name                 = var.scheduled_start_stop_query_alert_name != null ? var.scheduled_start_stop_query_alert_name : "SequencedStartStop_AzFunc"
  resource_group_name  = azurerm_resource_group.this.name
  scopes               = var.sequenced_query_alert_scopes != [] ? toset([azurerm_application_insights.app_insights.id]) : var.sequenced_query_alert_scopes
  severity             = 4
  tags                 = local.combined_hidden_link_tags
  window_duration      = "PT5M"
  action {
    action_groups = var.sequenced_query_action_groups != [] ? toset([azurerm_monitor_action_group.notification_group_ag.id]) : var.sequenced_query_action_groups
  }
  criteria {
    operator                = "GreaterThan"
    query                   = <<-EOT
    traces
    | where (operation_Name contains "Scheduled")
    | where (message hasprefix "~Sequenced")
    | extend output = substring(message,1)
    | summarize by message, output
    | project output
  EOT
    threshold               = 0
    time_aggregation_method = "Count"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }
}

resource "azurerm_monitor_smart_detector_alert_rule" "app_insights_anomalies_detector" {
  description         = "Failure Anomalies notifies you of an unusual rise in the rate of failed HTTP requests or dependency calls."
  detector_type       = "FailureAnomaliesDetector"
  frequency           = "PT1M"
  name                = "Failure Anomalies - ${azurerm_application_insights.app_insights.name}"
  resource_group_name = azurerm_resource_group.this.name
  scope_resource_ids  = [azurerm_application_insights.app_insights.id]
  severity            = "Sev3"
  tags                = local.solution_merged_tags
  action_group {
    ids = [azurerm_monitor_action_group.app_insights_ag.id]
  }
}

locals {
  storage_merged_ip_rules = concat(
    split(",", azurerm_windows_function_app.function_app.outbound_ip_addresses),
    split(",", azurerm_windows_function_app.function_app.possible_outbound_ip_addresses),
    azurerm_logic_app_workflow.logic_app_auto_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.workflow_endpoint_ip_addresses,
    var.storage_account_firewall_user_ip_rules
  )

  all_solution_ips = toset(concat(
    split(",", azurerm_windows_function_app.function_app.outbound_ip_addresses),
    split(",", azurerm_windows_function_app.function_app.possible_outbound_ip_addresses),
    azurerm_logic_app_workflow.logic_app_auto_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.workflow_endpoint_ip_addresses,
  ))
}

resource "azurerm_storage_account_network_rules" "storage_rules" {
  storage_account_id         = azurerm_storage_account.storage.id
  default_action             = var.storage_account_firewall_default_action
  bypass                     = var.storage_account_firewall_bypass
  virtual_network_subnet_ids = var.storage_account_firewall_subnet_ids
  ip_rules                   = local.storage_merged_ip_rules
}


resource "azurerm_role_assignment" "client_blob_owner" {
  count                = var.use_user_assigned_identity == true && var.assign_current_client_blob_owner == true ? 1 : 0
  principal_id         = data.azurerm_client_config.current.object_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage Blob Data Owner"
}

resource "azurerm_role_assignment" "client_smb_contributor" {
  count                = var.use_user_assigned_identity == true && var.assign_current_client_smb_contributor == true ? 1 : 0
  principal_id         = data.azurerm_client_config.current.object_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage File Data SMB Share Contributor"
}

resource "azurerm_role_assignment" "client_queue_contributor" {
  count                = var.use_user_assigned_identity == true && var.assign_current_client_queue_contributor == true ? 1 : 0
  principal_id         = data.azurerm_client_config.current.object_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage Queue Data Contributor"
}

resource "azurerm_role_assignment" "client_table_contributor" {
  count                = var.use_user_assigned_identity == true && var.assign_current_client_table_contributor == true ? 1 : 0
  principal_id         = data.azurerm_client_config.current.object_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage Table Data Contributor"
}

resource "azurerm_storage_account" "storage" {
  depends_on                      = [
  azurerm_role_assignment.client_blob_owner[0],
  azurerm_role_assignment.client_queue_contributor[0],
  azurerm_role_assignment.client_smb_contributor[0],
  azurerm_role_assignment.client_table_contributor[0]
  ]
  account_kind                    = "StorageV2"
  account_replication_type        = "LRS"
  account_tier                    = "Standard"
  allow_nested_items_to_be_public = false
  location                        = azurerm_resource_group.this.location
  min_tls_version                 = "TLS1_2"
  name                            = var.storage_account_name != null ? var.storage_account_name : "sa${var.name}"
  resource_group_name             = azurerm_resource_group.this.name
  tags                            = local.solution_merged_tags
  public_network_access_enabled   = var.storage_account_public_network_access_enabled
  shared_access_key_enabled       = var.storage_account_shared_access_keys_enabled

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }
}

resource "azurerm_storage_container" "web_jobs_hosts" {
  name                 = "azure-webjobs-hosts"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_container" "web_jobs_secrets" {
  name                 = "azure-webjobs-secrets"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_queue" "auto_update_request_queue" {
  name                 = "auto-update-request-queue"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_queue" "create_alert_request" {
  name                 = "create-alert-request"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_queue" "execution_request" {
  name                 = "execution-request"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_queue" "orchestration_request" {
  name                 = "orchestration-request"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_queue" "savings_request_queue" {
  name                 = "savings-request-queue"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_table" "auto_update_request_details_store_table" {
  name                 = "autoupdaterequestdetailsstoretable"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_table" "requests_store_stable" {
  name                 = "requeststoretable"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_storage_table" "subscription_requests_store_stable" {
  name                 = "subscriptionrequeststoretable"
  storage_account_name = azurerm_storage_account.storage.name
}

resource "azurerm_service_plan" "fnc_asp" {
  location            = azurerm_resource_group.this.location
  name                = var.app_service_plan_name != null ? var.app_service_plan_name : "asp-${var.name}"
  os_type             = "Windows"
  resource_group_name = azurerm_resource_group.this.name
  sku_name            = "Y1"
  tags                = local.solution_merged_tags
}

locals {
  default_app_settings = {
    AzureWebJobsDisableHomepage                         = "true"
    WEBSITE_CONTENTAZUREFILECONNECTIONSTRING            = "DefaultEndpointsProtocol=https;AccountName=${azurerm_storage_account.storage.name};AccountKey=${azurerm_storage_account.storage.primary_access_key}"
    WEBSITE_RUN_FROM_PACKAGE                            = var.start_stop_source_url
    APPLICATIONINSIGHTS_CONNECTION_STRING               = azurerm_application_insights.app_insights.connection_string
    APPINSIGHTS_INSTRUMENTATIONKEY                      = azurerm_application_insights.app_insights.instrumentation_key
    SOURCE_CODE_ORIGIN                                  = var.attempt_fetch_remote_start_stop_code == true ? var.start_stop_source_url : "local"
    "AzureClientOptions:ApplicationInsightName"         = var.app_insights_name != null ? var.app_insights_name : "appi-${var.name}"
    MSDEPLOY_RENAME_LOCKED_FILES                        = "1"
    "AzureClientOptions:ApplicationInsightRegion"       = azurerm_resource_group.this.location
    "AzureClientOptions:AutoUpdateRegionsUri"           = "https://startstopv2prod.blob.core.windows.net/artifacts/AutoUpdateRegionsGA.json"
    "AzureClientOptions:AutoUpdateTemplateUri"          = "https://startstopv2prod.blob.core.windows.net/artifacts/ssv2autoupdate.json"
    "AzureClientOptions:AzEnabled"                      = "false"
    "AzureClientOptions:AzureEnvironment"               = "AzureGlobalCloud"
    "AzureClientOptions:EnableAutoUpdate"               = "true"
    "AzureClientOptions:FunctionAppName"                = var.function_app_name != null ? var.function_app_name : "fnc-${var.name}"
    "AzureClientOptions:ResourceGroup"                  = azurerm_resource_group.this.name
    "AzureClientOptions:ResourceGroupRegion"            = azurerm_resource_group.this.location
    "AzureClientOptions:StorageAccountName"             = azurerm_storage_account.storage.name
    "AzureClientOptions:SubscriptionId"                 = data.azurerm_client_config.current.subscription_id
    "AzureClientOptions:TenantId"                       = data.azurerm_client_config.current.tenant_id
    "AzureClientOptions:Version"                        = "1.1.20221110.1"
    AzureWebJobsDisableHomepage                         = "true"
    "CentralizedLoggingOptions:InstrumentationKey"      = var.microsoft_instrumentation_key != null ? var.microsoft_instrumentation_key : "294eafc8-410b-4170-aecb-dfaa5cb6eeaa"
    "CentralizedLoggingOptions:Version"                 = "1.1.20221110.1"
    "StorageOptions:AutoUpdateRequestDetailsStoreTable" = azurerm_storage_table.auto_update_request_details_store_table.name
    "StorageOptions:AutoUpdateRequestQueue"             = azurerm_storage_queue.auto_update_request_queue.name
    "StorageOptions:CreateAutoStopAlertRequestQueue"    = azurerm_storage_queue.create_alert_request.name
    "StorageOptions:ExecutionRequestQueue"              = azurerm_storage_queue.execution_request.name
    "StorageOptions:OrchestrationRequestQueue"          = azurerm_storage_queue.orchestration_request.name
    "StorageOptions:RequestStoreTable"                  = azurerm_storage_table.requests_store_stable.name
    "StorageOptions:SavingsRequestQueue"                = azurerm_storage_queue.savings_request_queue.name
    "StorageOptions:StorageAccountConnectionString"     = "DefaultEndpointsProtocol=https;AccountName=${azurerm_storage_account.storage.name};AccountKey=${azurerm_storage_account.storage.primary_access_key}"
    "StorageOptions:SubscriptionRequestStoreTable"      = azurerm_storage_table.subscription_requests_store_stable.name
  }
  new_app_settings = {
    "AzureWebJobsStorage__blobServiceUri"  = "https://${azurerm_storage_account.storage.name}.blob.core.windows.net"
    "AzureWebJobsStorage__queueServiceUri" = "https://${azurerm_storage_account.storage.name}.queue.core.windows.net"
    "AzureWebJobsStorage__tableServiceUri" = "https://${azurerm_storage_account.storage.name}.table.core.windows.net"
    AzureWebJobsStorage                    = "DefaultEndpointsProtocol=https;AccountName=${azurerm_storage_account.storage.name};AccountKey=${azurerm_storage_account.storage.primary_access_key}"
    APPLICATIONINSIGHTS_CONNECTION_STRING  = azurerm_application_insights.app_insights.connection_string
    APPINSIGHTS_INSTRUMENTATIONKEY         = azurerm_application_insights.app_insights.instrumentation_key
    FUNCTIONS_EXTENSION_VERSION            = "~4"
    WEBSITE_NODE_DEFAULT_VERSION           = "~10"
    "WEBSITE_CONTENTSHARE"                 = var.function_app_name != null ? var.function_app_name : "fnc-${var.name}"
  }
  app_settings = merge(local.new_app_settings, local.default_app_settings)
}

resource "azurerm_windows_function_app" "function_app" {
  app_settings = local.app_settings

  builtin_logging_enabled    = false
  client_certificate_enabled = true
  location                   = azurerm_resource_group.this.location
  name                       = var.function_app_name != null ? var.function_app_name : "fnc-${var.name}"
  resource_group_name        = azurerm_resource_group.this.name
  service_plan_id            = azurerm_service_plan.fnc_asp.id
  storage_account_access_key = azurerm_storage_account.storage.primary_access_key
  storage_account_name       = azurerm_storage_account.storage.name
  https_only                 = var.function_app_https_only
  tags                       = local.solution_merged_tags

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == false ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  site_config {
    application_stack {
      dotnet_version = "v6.0"
    }

    ftps_state = "FtpsOnly"
  }
}

resource "azurerm_user_assigned_identity" "uid" {
  count               = var.use_user_assigned_identity == true ? 1 : 0
  location            = azurerm_resource_group.this.location
  name                = var.user_assigned_identity_name != null ? var.user_assigned_identity_name : "uid-ststv2"
  resource_group_name = azurerm_resource_group.this.name
}

resource "azurerm_role_assignment" "id_contributor" {
  principal_id         = var.use_user_assigned_identity == true ? azurerm_user_assigned_identity.uid[0].principal_id : azurerm_windows_function_app.function_app.identity[0].principal_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Contributor"
}

resource "azurerm_role_assignment" "id_blob_owner" {
  count                = var.use_user_assigned_identity == true ? 1 : 0
  principal_id         = var.use_user_assigned_identity == true ? azurerm_user_assigned_identity.uid[0].principal_id : azurerm_windows_function_app.function_app.identity[0].principal_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage Blob Data Owner"
}

resource "azurerm_role_assignment" "id_smb_contributor" {
  count                = var.use_user_assigned_identity == true ? 1 : 0
  principal_id         = var.use_user_assigned_identity == true ? azurerm_user_assigned_identity.uid[0].principal_id : azurerm_windows_function_app.function_app.identity[0].principal_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage File Data SMB Share Contributor"
}

resource "azurerm_role_assignment" "id_queue_contributor" {
  count                = var.use_user_assigned_identity == true ? 1 : 0
  principal_id         = var.use_user_assigned_identity == true ? azurerm_user_assigned_identity.uid[0].principal_id : azurerm_windows_function_app.function_app.identity[0].principal_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage Queue Data Contributor"
}

resource "azurerm_role_assignment" "id_table_contributor" {
  count                = var.use_user_assigned_identity == true ? 1 : 0
  principal_id         = var.use_user_assigned_identity == true ? azurerm_user_assigned_identity.uid[0].principal_id : azurerm_windows_function_app.function_app.identity[0].principal_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Storage Table Data Contributor"
}

resource "time_sleep" "wait_120_seconds" {
  depends_on = [azurerm_role_assignment.id_contributor]

  create_duration = "120s"
}

resource "azurerm_logic_app_workflow" "logic_app_auto_stop" {
  depends_on          = [time_sleep.wait_120_seconds]
  enabled             = var.auto_stop_logic_app_enabled
  location            = azurerm_resource_group.this.location
  name                = var.auto_stop_logic_app_name != null ? var.auto_stop_logic_app_name : "ststv2_vms_AutoStop"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.solution_merged_tags

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }
}


resource "azurerm_logic_app_action_custom" "auto_stop_terminate" {
  depends_on = [
    time_sleep.wait_120_seconds,
    azurerm_logic_app_action_custom.auto_stop_function,
  ]

  body = jsonencode({
    "actions" : {
      "Terminate" : {
        "inputs" : {
          "runError" : {
            "code" : "@{outputs('AutoStop')['statusCode']}",
            "message" : "@{body('AutoStop')}"
          },
          "runStatus" : "Failed"
        },
        "type" : "Terminate"
      }
    },
    "runAfter" : {
      "Function-Try" : ["Failed", "Skipped", "TimedOut"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_auto_stop.id
  name         = "Function-Catch"
}

resource "azurerm_logic_app_action_custom" "auto_stop_success_function" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.auto_stop_terminate
  ]
  body = jsonencode({
    "runAfter" : {
      "Function-Try" : ["Succeeded"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_auto_stop.id
  name         = "Function-Success"
}

resource "azurerm_logic_app_action_custom" "auto_stop_function" {
  depends_on = [
    time_sleep.wait_120_seconds
  ]

  body = jsonencode({
    "actions" : {
      "AutoStop" : {
        "inputs" : {
          "body" : {
            "Action" : "stop",
            "AutoStop_Condition" : "LessThan",
            "AutoStop_Description" : "Alert to stop the VM if the CPU % exceed the threshold",
            "AutoStop_Frequency" : "00:05:00",
            "AutoStop_MetricName" : "Percentage CPU",
            "AutoStop_Severity" : "2",
            "AutoStop_Threshold" : "5",
            "AutoStop_TimeAggregationOperator" : "Average",
            "AutoStop_TimeWindow" : "06:00:00",
            "EnableClassic" : false,
            "RequestScopes" : {
              "ResourceGroups" : "${toset(var.auto_stop_resource_group_scopes)}"
            }
          },
          "function" : {
            "id" : "${azurerm_windows_function_app.function_app.id}/functions/Scheduled"
          }
        },
        "type" : "Function"
      }
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_auto_stop.id
  name         = "Function-Try"
}

resource "azurerm_logic_app_trigger_recurrence" "auto_stop_recurrence_trigger" {
  depends_on = [
    azurerm_windows_function_app.function_app
  ]
  frequency    = var.auto_stop_logic_app_evaluation_frequency
  interval     = var.auto_stop_logic_app_evaluation_interval_number
  start_time   = var.auto_stop_logic_app_evaluation_interval_start_time
  time_zone    = var.logic_app_default_timezone != null ? var.logic_app_default_timezone : "GMT Standard Time"
  logic_app_id = azurerm_logic_app_workflow.logic_app_auto_stop.id
  name         = "Recurrence"

  dynamic "schedule" {
    for_each = [for s in var.auto_stop_schedules : s if length(s.days) > 0 || length(s.hours) > 0 || length(s.minutes) > 0]
    content {
      on_these_days    = schedule.value.days
      at_these_hours   = schedule.value.hours
      at_these_minutes = schedule.value.minutes
    }
  }
}

resource "azurerm_logic_app_workflow" "logic_app_scheduled_start" {
  enabled             = var.scheduled_start_logic_app_enabled
  location            = azurerm_resource_group.this.location
  name                = var.scheduled_start_logic_app_name != null ? var.scheduled_start_logic_app_name : "ststv2_vms_Scheduled_start"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.solution_merged_tags

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }
}


resource "azurerm_logic_app_action_custom" "scheduled_start_terminate" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.scheduled_start_start_function
  ]

  body = jsonencode({
    "actions" : {
      "Terminate" : {
        "inputs" : {
          "runError" : {
            "code" : "@{outputs('Scheduled')['statusCode']}",
            "message" : "@{body('Scheduled')}"
          },
          "runStatus" : "Failed"
        },
        "type" : "Terminate"
      }
    },
    "runAfter" : {
      "Function-Try" : ["Failed", "Skipped", "TimedOut"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_start.id
  name         = "Function-Catch"
}

resource "azurerm_logic_app_action_custom" "scheduled_start_success_function" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.scheduled_start_start_function
  ]

  body = jsonencode({
    "runAfter" : {
      "Function-Try" : ["Succeeded"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_start.id
  name         = "Function-Success"
}

resource "azurerm_logic_app_action_custom" "scheduled_start_start_function" {
  depends_on = [
    time_sleep.wait_120_seconds,
    azurerm_logic_app_action_custom.auto_stop_function
  ]
  body = jsonencode({
    "actions" : {
      "Scheduled" : {
        "inputs" : {
          "body" : {
            "Action" : "start",
            "EnableClassic" : false,
            "RequestScopes" : {
              "ResourceGroups" : "${toset(var.scheduled_start_resource_group_scopes)}"
            }
          },
          "function" : {
            "id" : "${azurerm_windows_function_app.function_app.id}/functions/Scheduled"
          }
        },
        "type" : "Function"
      }
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_start.id
  name         = "Function-Try"
}

resource "azurerm_logic_app_trigger_recurrence" "scheduled_start_daily_trigger" {
  depends_on = [
    time_sleep.wait_120_seconds
  ]

  frequency    = var.scheduled_start_logic_app_evaluation_frequency
  interval     = var.scheduled_start_logic_app_evaluation_interval_number
  start_time   = var.scheduled_start_logic_app_evaluation_interval_start_time
  time_zone    = var.logic_app_default_timezone != null ? var.logic_app_default_timezone : "GMT Standard Time"
  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_start.id
  name         = "Recurrence"

  dynamic "schedule" {
    for_each = [for s in var.scheduled_start_schedules : s if length(s.days) > 0 || length(s.hours) > 0 || length(s.minutes) > 0]
    content {
      on_these_days    = schedule.value.days
      at_these_hours   = schedule.value.hours
      at_these_minutes = schedule.value.minutes
    }
  }
}

resource "azurerm_logic_app_workflow" "logic_app_scheduled_stop" {
  enabled             = var.scheduled_stop_logic_app_enabled
  location            = azurerm_resource_group.this.location
  name                = var.scheduled_stop_logic_app_name != null ? var.scheduled_stop_logic_app_name : "ststv2_vms_Scheduled_stop"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.solution_merged_tags

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }
}

resource "azurerm_logic_app_action_custom" "scheduled_stop_failed_function" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.scheduled_stop_stop_function
  ]

  body = jsonencode({
    "actions" : {
      "Terminate" : {
        "inputs" : {
          "runError" : {
            "code" : "@{outputs('Scheduled')['statusCode']}",
            "message" : "@{body('Scheduled')}"
          },
          "runStatus" : "Failed"
        },
        "type" : "Terminate"
      }
    },
    "runAfter" : {
      "Function-Try" : ["Failed", "Skipped", "TimedOut"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_stop.id
  name         = "Function-Catch"
}

resource "azurerm_logic_app_action_custom" "scheduled_stop_succeeded_function" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.scheduled_stop_stop_function,
  ]

  body = jsonencode({
    "runAfter" : {
      "Function-Try" : ["Succeeded"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_stop.id
  name         = "Function-Success"
}

resource "azurerm_logic_app_action_custom" "scheduled_stop_stop_function" {
  depends_on = [
    time_sleep.wait_120_seconds,
    azurerm_logic_app_action_custom.scheduled_start_start_function
  ]
  body = jsonencode({
    "actions" : {
      "Scheduled" : {
        "inputs" : {
          "body" : {
            "Action" : "stop",
            "EnableClassic" : false,
            "RequestScopes" : {
              "ResourceGroups" : "${toset(var.scheduled_stop_resource_group_scopes)}"
            }
          },
          "function" : {
            "id" : "${azurerm_windows_function_app.function_app.id}/functions/Scheduled"
          }
        },
        "type" : "Function"
      }
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_stop.id
  name         = "Function-Try"
}

resource "azurerm_logic_app_trigger_recurrence" "scheduled_stop_daily_recurrence" {
  depends_on = [
    azurerm_windows_function_app.function_app
  ]
  frequency    = var.scheduled_stop_logic_app_evaluation_frequency
  interval     = var.scheduled_stop_logic_app_evaluation_interval_number
  start_time   = var.scheduled_stop_logic_app_evaluation_interval_start_time
  time_zone    = var.logic_app_default_timezone != null ? var.logic_app_default_timezone : "GMT Standard Time"
  logic_app_id = azurerm_logic_app_workflow.logic_app_scheduled_stop.id
  name         = "Recurrence"

  dynamic "schedule" {
    for_each = [for s in var.scheduled_stop_schedules : s if length(s.days) > 0 || length(s.hours) > 0 || length(s.minutes) > 0]
    content {
      on_these_days    = schedule.value.days
      at_these_hours   = schedule.value.hours
      at_these_minutes = schedule.value.minutes
    }
  }
}

resource "azurerm_logic_app_workflow" "logic_app_sequenced_start" {
  enabled             = var.sequenced_start_logic_app_enabled
  location            = azurerm_resource_group.this.location
  name                = var.sequenced_start_logic_app_name != null ? var.sequenced_start_logic_app_name : "ststv2_vms_Sequenced_start"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.solution_merged_tags

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }
}

resource "azurerm_logic_app_action_custom" "sequenced_start_failed_action" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.sequenced_start_start_function
  ]

  body = jsonencode({
    "actions" : {
      "Terminate" : {
        "inputs" : {
          "runError" : {
            "code" : "@{outputs('Scheduled')['statusCode']}",
            "message" : "@{body('Scheduled')}"
          },
          "runStatus" : "Failed"
        },
        "type" : "Terminate"
      }
    },
    "runAfter" : {
      "Function-Try" : ["Failed", "Skipped", "TimedOut"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_start.id
  name         = "Function-Catch"
}

resource "azurerm_logic_app_action_custom" "sequenced_start_success_action" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.sequenced_start_start_function
  ]

  body = jsonencode({
    "runAfter" : {
      "Function-Try" : ["Succeeded"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_start.id
  name         = "Function-Success"
}

resource "azurerm_logic_app_action_custom" "sequenced_start_start_function" {
  depends_on = [
    time_sleep.wait_120_seconds,
    azurerm_logic_app_action_custom.scheduled_stop_stop_function
  ]
  body = jsonencode({
    "actions" : {
      "Scheduled" : {
        "inputs" : {
          "body" : {
            "Action" : "start",
            "RequestScopes" : {
              "ResourceGroups" : "${toset(var.sequenced_start_resource_group_scopes)}",
              "Sequenced" : true
            }
          },
          "function" : {
            "id" : "${azurerm_windows_function_app.function_app.id}/functions/Scheduled"
          }
        },
        "type" : "Function"
      }
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_start.id
  name         = "Function-Try"
}


resource "azurerm_logic_app_trigger_recurrence" "sequenced_start_daily_trigger" {
  depends_on = [
    azurerm_windows_function_app.function_app
  ]
  frequency    = var.sequenced_start_logic_app_evaluation_frequency
  interval     = var.sequenced_start_logic_app_evaluation_interval_number
  start_time   = var.sequenced_start_logic_app_evaluation_interval_start_time
  time_zone    = var.logic_app_default_timezone != null ? var.logic_app_default_timezone : "GMT Standard Time"
  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_start.id
  name         = "Recurrence"

  dynamic "schedule" {
    for_each = [for s in var.sequenced_start_schedules : s if length(s.days) > 0 || length(s.hours) > 0 || length(s.minutes) > 0]
    content {
      on_these_days    = schedule.value.days
      at_these_hours   = schedule.value.hours
      at_these_minutes = schedule.value.minutes
    }
  }
}

resource "azurerm_logic_app_workflow" "logic_app_sequenced_stop" {
  enabled             = var.sequenced_stop_logic_app_enabled
  location            = azurerm_resource_group.this.location
  name                = var.sequenced_stop_logic_app_name != null ? var.sequenced_stop_logic_app_name : "ststv2_vms_Sequenced_stop"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.solution_merged_tags

  dynamic "identity" {
    for_each = var.use_user_assigned_identity == true ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = toset([azurerm_user_assigned_identity.uid[0].id])
    }
  }
}


resource "azurerm_logic_app_action_custom" "sequenced_stop_termination_function" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.sequenced_stop_stop_action,

  ]

  body = jsonencode({
    "actions" : {
      "Terminate" : {
        "inputs" : {
          "runError" : {
            "code" : "@{outputs('Scheduled')['statusCode']}",
            "message" : "@{body('Scheduled')}"
          },
          "runStatus" : "Failed"
        },
        "type" : "Terminate"
      }
    },
    "runAfter" : {
      "Function-Try" : ["Failed", "Skipped", "TimedOut"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_stop.id
  name         = "Function-Catch"
}

resource "azurerm_logic_app_action_custom" "sequenced_stop_success_action" {
  depends_on = [
    azurerm_windows_function_app.function_app,
    azurerm_logic_app_action_custom.sequenced_stop_stop_action,
  ]

  body = jsonencode({
    "runAfter" : {
      "Function-Try" : ["Succeeded"]
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_stop.id
  name         = "Function-Success"
}

resource "azurerm_logic_app_action_custom" "sequenced_stop_stop_action" {
  depends_on = [
    time_sleep.wait_120_seconds,
    azurerm_logic_app_action_custom.sequenced_start_start_function
  ]
  body = jsonencode({
    "actions" : {
      "Scheduled" : {
        "inputs" : {
          "body" : {
            "Action" : "stop",
            "RequestScopes" : {
              "ResourceGroups" : "${toset(var.sequenced_stop_resource_group_scopes)}",
              "Sequenced" : true
            }
          },
          "function" : {
            "id" : "${azurerm_windows_function_app.function_app.id}/functions/Scheduled"
          }
        },
        "type" : "Function"
      }
    },
    "type" : "Scope"
  })

  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_stop.id
  name         = "Function-Try"
}

resource "azurerm_logic_app_trigger_recurrence" "sequenced_stop_daily_trigger" {
  depends_on = [
    azurerm_windows_function_app.function_app
  ]
  frequency    = var.sequenced_stop_logic_app_evaluation_frequency
  interval     = var.sequenced_stop_logic_app_evaluation_interval_number
  start_time   = var.sequenced_stop_logic_app_evaluation_interval_start_time
  time_zone    = var.logic_app_default_timezone != null ? var.logic_app_default_timezone : "GMT Standard Time"
  logic_app_id = azurerm_logic_app_workflow.logic_app_sequenced_stop.id
  name         = "Recurrence"

  dynamic "schedule" {
    for_each = [for s in var.sequenced_stop_schedules : s if length(s.days) > 0 || length(s.hours) > 0 || length(s.minutes) > 0]
    content {
      on_these_days    = schedule.value.days
      at_these_hours   = schedule.value.hours
      at_these_minutes = schedule.value.minutes
    }
  }
}

locals {
  dashboard_tag = {
    hidden-title = "StartStopV2_Dashboard"
  }

  merged_dashboard_tags = merge(local.dashboard_tag, local.solution_merged_tags)

  dashboard = {

  }
}

resource "azurerm_portal_dashboard" "dashboard" {
  dashboard_properties = <<DASHBOARD_PROPERTIES
{
"lenses": {
      "0": {
        "order": 0,
        "parts": {
          "0": {
            "position": {
              "x": 0,
              "y": 0,
              "colSpan": 3,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [],
              "type": "Extension/HubsExtension/PartType/MarkdownPart",
              "settings": {
                "content": {
                  "settings": {
                    "content": "This is your StartStop VMs dashboard.\n\nFor more information view [doc](https://github.com/microsoft/startstopv2-deployments/blob/main/README.md)\n\n**Deployment information**\n> **Subscription :** CyberScot-Prd  \n> **Resource Group :** ${azurerm_application_insights.app_insights.resource_group_name}  \n> **Application Insights :** ${azurerm_application_insights.app_insights.name}",
                    "title": "Welcome!",
                    "subtitle": "",
                    "markdownSource": 1
                  }
                }
              }
            }
          },
          "1": {
            "position": {
              "x": 3,
              "y": 0,
              "colSpan": 5,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  }
                },
                {
                  "name": "Query",
                  "value": "traces \n| where customDimensions.prop__Name == \"VmExecutionsAttempted\" and customDimensions.prop__Successful == true\n| project      \n    action = tostring(customDimensions.prop__ActionType),\n    value = customDimensions.prop__value,\n    timestamp\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\n"
                },
                {
                  "name": "TimeRange",
                  "value": "PT30M"
                },
                {
                  "name": "Dimensions",
                  "value": {
                    "xAxis": {
                      "name": "timestamp",
                      "type": "datetime"
                    },
                    "yAxis": [
                      {
                        "name": "request_count",
                        "type": "real"
                      }
                    ],
                    "splitBy": [
                      {
                        "name": "action",
                        "type": "string"
                      }
                    ],
                    "aggregation": "Sum"
                  }
                },
                {
                  "name": "Version",
                  "value": "1.0"
                },
                {
                  "name": "PartId",
                  "value": "1873282b-e618-432b-8147-bd0cfb34cf73"
                },
                {
                  "name": "PartTitle",
                  "value": "Successful Start and Stop Actions Taken"
                },
                {
                  "name": "PartSubTitle",
                  "value": "Total count of successful start and stop actions taken against your virtual machines by the StartStop service."
                },
                {
                  "name": "resourceTypeMode",
                  "value": "components"
                },
                {
                  "name": "ControlType",
                  "value": "FrameControlChart"
                },
                {
                  "name": "SpecificChart",
                  "value": "UnstackedColumn"
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {
                "content": {
                  "Query": "traces \n| where customDimensions.prop__Name == \"VmExecutionsAttempted\" and customDimensions.prop__Successful == true\n| project      \n    action = tostring(customDimensions.prop__ActionType),\n    value = customDimensions.prop__Value,\n    timestamp\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\n\n",
                  "LegendOptions": {
                    "isEnabled": true,
                    "position": "Bottom"
                  }
                }
              }
            }
          },
          "2": {
            "position": {
              "x": 8,
              "y": 0,
              "colSpan": 5,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "resourceTypeMode",
                  "value": "components",
                  "isOptional": true
                },
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  },
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "PartId",
                  "value": "1873282b-e618-432b-8147-bd0cfb34cf73",
                  "isOptional": true
                },
                {
                  "name": "Version",
                  "value": "1.0",
                  "isOptional": true
                },
                {
                  "name": "TimeRange",
                  "value": "PT30M",
                  "isOptional": true
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "Query",
                  "value": "traces \n| where customDimensions.prop__Name == \"VmExecutionsAttempted\" and customDimensions.prop__Successful == true\n| project      \n    action = tostring(customDimensions.prop__ActionType),\n    value = customDimensions.prop__value,\n    timestamp\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\n",
                  "isOptional": true
                },
                {
                  "name": "ControlType",
                  "value": "FrameControlChart",
                  "isOptional": true
                },
                {
                  "name": "SpecificChart",
                  "value": "UnstackedColumn",
                  "isOptional": true
                },
                {
                  "name": "PartTitle",
                  "value": "Successful Start and Stop Actions Taken",
                  "isOptional": true
                },
                {
                  "name": "PartSubTitle",
                  "value": "Total count of successful start and stop actions taken against your virtual machines by the StartStop service.",
                  "isOptional": true
                },
                {
                  "name": "Dimensions",
                  "value": {
                    "xAxis": {
                      "name": "timestamp",
                      "type": "datetime"
                    },
                    "yAxis": [
                      {
                        "name": "request_count",
                        "type": "real"
                      }
                    ],
                    "splitBy": [
                      {
                        "name": "action",
                        "type": "string"
                      }
                    ],
                    "aggregation": "Sum"
                  },
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {
                "content": {
                  "Query": "traces \n| where customDimensions.prop__Name == \"VmExecutionsAttempted\" and customDimensions.prop__Successful == false\n| project      \n    action = tostring(customDimensions.prop__ActionType),\n    value = customDimensions.prop__Value,\n    timestamp\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\n\n",
                  "ControlType": "AnalyticsGrid",
                  "LegendOptions": {
                    "isEnabled": true,
                    "position": "Bottom"
                  }
                }
              },
              "partHeader": {
                "title": "Failed Start and Stop Actions Taken",
                "subtitle": ""
              }
            }
          },
          "3": {
            "position": {
              "x": 0,
              "y": 4,
              "colSpan": 9,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "Version",
                  "value": "1.0"
                },
                {
                  "name": "PartId",
                  "value": "15b42e68-24a8-4715-ae79-067f634ce119"
                },
                {
                  "name": "PartTitle",
                  "value": "Recently attempted actions on VMs"
                },
                {
                  "name": "PartSubTitle",
                  "value": "Virtual machines which recently had a start or stop action attempted."
                },
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  }
                },
                {
                  "name": "Query",
                  "value": "traces\n| where customDimensions.prop__Name == \"VmExecutionsAttempted\"\n| project      \n  action = customDimensions.prop__ActionType,\n  virtual_machine = customDimensions.prop__ResourceName,\n  resource_group = customDimensions.prop__ResourceGroup,\n  subscription_ID = customDimensions.prop__SubscriptionId,\n  timestamp\n| order by timestamp desc\n"
                },
                {
                  "name": "TimeRange",
                  "value": "P1D"
                },
                {
                  "name": "resourceTypeMode",
                  "value": "components"
                },
                {
                  "name": "ControlType",
                  "value": "AnalyticsGrid"
                },
                {
                  "name": "Dimensions",
                  "isOptional": true
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "SpecificChart",
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {},
              "asset": {
                "idInputName": "ComponentId",
                "type": "ApplicationInsights"
              }
            }
          },
          "4": {
            "position": {
              "x": 9,
              "y": 4,
              "colSpan": 4,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  },
                  "isOptional": true
                },
                {
                  "name": "Dimensions",
                  "value": {
                    "xAxis": {
                      "name": "action",
                      "type": "string"
                    },
                    "yAxis": [
                      {
                        "name": "request_count",
                        "type": "real"
                      }
                    ],
                    "splitBy": [],
                    "aggregation": "Sum"
                  },
                  "isOptional": true
                },
                {
                  "name": "Query",
                  "value": "traces\n| where customDimensions.prop__Name == \"VmExecutionsAttempted\" and customDimensions.prop__Successful == true\n| project      \n    action = tostring(customDimensions.prop__ActionType),\n    value = toreal(customDimensions.prop__value),\n    timestamp\n| summarize request_count=sum(value) by action,bin(timestamp, 1h)\n",
                  "isOptional": true
                },
                {
                  "name": "PartTitle",
                  "value": "Start & Stop (%)",
                  "isOptional": true
                },
                {
                  "name": "PartSubTitle",
                  "value": "Total % count of start and stop action",
                  "isOptional": true
                },
                {
                  "name": "PartId",
                  "value": "08ad6984-455d-440c-9596-73760a4178c3",
                  "isOptional": true
                },
                {
                  "name": "Version",
                  "value": "1.0",
                  "isOptional": true
                },
                {
                  "name": "resourceTypeMode",
                  "value": "components",
                  "isOptional": true
                },
                {
                  "name": "TimeRange",
                  "value": "P30D",
                  "isOptional": true
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "ControlType",
                  "value": "FrameControlChart",
                  "isOptional": true
                },
                {
                  "name": "SpecificChart",
                  "value": "Donut",
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {
                "content": {
                  "Query": "traces\n| where customDimensions.prop__Name == \"VmExecutionsAttempted\" and customDimensions.prop__Successful == true\n| project      \n    action = tostring(customDimensions.prop__ActionType),\n    value = toreal(customDimensions.prop__Value),\n    timestamp\n| summarize request_count=sum(value) by action,bin(timestamp, 1h)\n\n",
                  "LegendOptions": {
                    "isEnabled": true,
                    "position": "Bottom"
                  }
                }
              }
            }
          },
          "5": {
            "position": {
              "x": 0,
              "y": 8,
              "colSpan": 6,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  }
                },
                {
                  "name": "Query",
                  "value": "(traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced)\n| project scenario = \"Sequenced\",      value = toreal(customDimensions.prop__value),      timestamp)\n| union\n(traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced) == false\n| project scenario = \"Scheduled\",      value = toreal(customDimensions.prop__value),      timestamp)\n| union\n(traces\n| where customDimensions.prop__Name == \"NoPiiAutoStopRequests\"\n| project scenario = \"AutoStop\",      value = toreal(customDimensions.prop__value),      timestamp)\n| summarize request_count=sum(value) by scenario,bin(timestamp, 15m)\n"
                },
                {
                  "name": "TimeRange",
                  "value": "PT1H"
                },
                {
                  "name": "Dimensions",
                  "value": {
                    "xAxis": {
                      "name": "timestamp",
                      "type": "datetime"
                    },
                    "yAxis": [
                      {
                        "name": "request_count",
                        "type": "real"
                      }
                    ],
                    "splitBy": [
                      {
                        "name": "scenario",
                        "type": "string"
                      }
                    ],
                    "aggregation": "Sum"
                  }
                },
                {
                  "name": "Version",
                  "value": "1.0"
                },
                {
                  "name": "PartId",
                  "value": "1b21d06a-2b57-4d5a-b912-1fe272b12de9"
                },
                {
                  "name": "PartTitle",
                  "value": "StartStop Scenarios"
                },
                {
                  "name": "PartSubTitle",
                  "value": "Count of recently executed schedules, sequenced, and auto stop scenarios."
                },
                {
                  "name": "resourceTypeMode",
                  "value": "components"
                },
                {
                  "name": "ControlType",
                  "value": "FrameControlChart"
                },
                {
                  "name": "SpecificChart",
                  "value": "StackedColumn"
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {
                "content": {
                  "Query": "(traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced)\n| project scenario = \"Sequenced\",      value = toreal(customDimensions.prop__Value),      timestamp)\n| union\n(traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced) == false\n| project scenario = \"Scheduled\",      value = toreal(customDimensions.prop__Value),      timestamp)\n| union\n(traces\n| where customDimensions.prop__Name == \"NoPiiAutoStopRequests\"\n| project scenario = \"AutoStop\",      value = toreal(customDimensions.prop__Value),      timestamp)\n| summarize request_count=sum(value) by scenario,bin(timestamp, 15m)\n\n",
                  "LegendOptions": {
                    "isEnabled": true,
                    "position": "Bottom"
                  }
                }
              }
            }
          },
          "6": {
            "position": {
              "x": 6,
              "y": 8,
              "colSpan": 4,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  },
                  "isOptional": true
                },
                {
                  "name": "Dimensions",
                  "value": {
                    "xAxis": {
                      "name": "scenario",
                      "type": "string"
                    },
                    "yAxis": [
                      {
                        "name": "request_count",
                        "type": "real"
                      }
                    ],
                    "splitBy": [],
                    "aggregation": "Sum"
                  },
                  "isOptional": true
                },
                {
                  "name": "Query",
                  "value": "(traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced)\n| project scenario = \"Sequenced\",      value = toreal(customDimensions.prop__value),      timestamp)\n| union (traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced) == false\n| project scenario = \"Scheduled\",      value = toreal(customDimensions.prop__value),      timestamp)\n| union (traces\n| where customDimensions.prop__Name == \"NoPiiAutoStopRequests\"\n| project scenario = \"AutoStop\",      value = toreal(customDimensions.prop__value),      timestamp)\n| summarize request_count=sum(value) by scenario\n",
                  "isOptional": true
                },
                {
                  "name": "PartTitle",
                  "value": "Count by Scenarios",
                  "isOptional": true
                },
                {
                  "name": "PartSubTitle",
                  "value": "Count of recently executed Scenarios",
                  "isOptional": true
                },
                {
                  "name": "PartId",
                  "value": "7c4418b6-9831-46ae-b5d9-5c6b611ae16f",
                  "isOptional": true
                },
                {
                  "name": "Version",
                  "value": "1.0",
                  "isOptional": true
                },
                {
                  "name": "resourceTypeMode",
                  "value": "components",
                  "isOptional": true
                },
                {
                  "name": "TimeRange",
                  "value": "P30D",
                  "isOptional": true
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "ControlType",
                  "value": "FrameControlChart",
                  "isOptional": true
                },
                {
                  "name": "SpecificChart",
                  "value": "Donut",
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {
                "content": {
                  "Query": "(traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced)\n| project scenario = \"Sequenced\",      value = toreal(customDimensions.prop__Value),      timestamp)\n| union (traces\n| where customDimensions.prop__Name == \"NoPiiScheduleRequests\" and tobool(customDimensions.prop__Sequenced) == false\n| project scenario = \"Scheduled\",      value = toreal(customDimensions.prop__Value),      timestamp)\n| union (traces\n| where customDimensions.prop__Name == \"NoPiiAutoStopRequests\"\n| project scenario = \"AutoStop\",      value = toreal(customDimensions.prop__Value),      timestamp)\n| summarize request_count=sum(value) by scenario\n\n",
                  "LegendOptions": {
                    "isEnabled": true,
                    "position": "Bottom"
                  }
                }
              }
            }
          },
          "7": {
            "position": {
              "x": 10,
              "y": 8,
              "colSpan": 3,
              "rowSpan": 4
            },
            "metadata": {
              "inputs": [
                {
                  "name": "ComponentId",
                  "value": {
                    "SubscriptionId": "${data.azurerm_client_config.current.subscription_id}",
                    "ResourceGroup": "${azurerm_application_insights.app_insights.resource_group_name}",
                    "Name": "${azurerm_application_insights.app_insights.name}",
                    "ResourceId": "${azurerm_application_insights.app_insights.id}"
                  },
                  "isOptional": true
                },
                {
                  "name": "Dimensions",
                  "value": {
                    "xAxis": {
                      "name": "resource_group",
                      "type": "string"
                    },
                    "yAxis": [
                      {
                        "name": "count_",
                        "type": "long"
                      }
                    ],
                    "splitBy": [],
                    "aggregation": "Sum"
                  },
                  "isOptional": true
                },
                {
                  "name": "Query",
                  "value": "traces\n| where customDimensions.prop__Name == \"VmExecutionsAttempted\"\n| project  resource_group = tostring(customDimensions.prop__ResourceGroup)\n| summarize count() by resource_group\n",
                  "isOptional": true
                },
                {
                  "name": "PartTitle",
                  "value": "Count by Resource Group",
                  "isOptional": true
                },
                {
                  "name": "PartSubTitle",
                  "value": "Resource Groups which recently had a start or stop action",
                  "isOptional": true
                },
                {
                  "name": "PartId",
                  "value": "2aef6442-2811-49df-b349-d58e1d868ab5",
                  "isOptional": true
                },
                {
                  "name": "Version",
                  "value": "1.0",
                  "isOptional": true
                },
                {
                  "name": "resourceTypeMode",
                  "value": "components",
                  "isOptional": true
                },
                {
                  "name": "TimeRange",
                  "value": "P30D",
                  "isOptional": true
                },
                {
                  "name": "DashboardId",
                  "isOptional": true
                },
                {
                  "name": "ControlType",
                  "value": "FrameControlChart",
                  "isOptional": true
                },
                {
                  "name": "SpecificChart",
                  "value": "Donut",
                  "isOptional": true
                },
                {
                  "name": "Scope",
                  "isOptional": true
                },
                {
                  "name": "DraftRequestParameters",
                  "isOptional": true
                },
                {
                  "name": "LegendOptions",
                  "isOptional": true
                },
                {
                  "name": "IsQueryContainTimeRange",
                  "isOptional": true
                }
              ],
              "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart",
              "settings": {}
            }
          }
        }
      }
    }
}
DASHBOARD_PROPERTIES
  location             = azurerm_resource_group.this.location
  name                 = var.dashboard_name != null ? var.dashboard_name : "StartStopV2_Dashboard"
  resource_group_name  = azurerm_resource_group.this.name
  tags                 = local.merged_dashboard_tags
}

