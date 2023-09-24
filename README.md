# Information

All credit for this solution goes to Microsoft and documentation on the solution specifically can be found at [Microsoft's GitHub repo ](https://github.com/microsoft/startstopv2-deployments)and the [documentation on Microsoft Docs](https://learn.microsoft.com/en-us/azure/azure-functions/start-stop-vms/overview)

This module also utilised the use of [aztfexport](https://github.com/Azure/aztfexport), so again, full credit to Microsoft :smile:

The code in this repo is purely for deploying the Microsoft solution using terraform, rather than the default ARM template deployment

For any specific issues with the terraform deployment, you can raise issues and improvements [here](https://github.com/cyber-scot/terraform-azurerm-vm-start-stop-solution/issues), [with the azurerm provider](https://github.com/hashicorp/terraform-provider-azurerm) or [with terraform itself](https://github.com/hashicorp/terraform)

## Potential Infrastructure Improvements for v1.1.0 (PRs welcome)

These are some known issues in the infrastructure for the v1.0.0 deployment.  PRs are welcome on these suggestions for a v1.1.0 release.  These issues should also exist in the Microsoft ARM template deployment as the v1.0.0 build aims to be a like-for-like replacement with some extra utilities on naming and configuration options

- Enabling the Storage Account firewall causes logic app deployment issues. It is disabled by default in the Microsoft deployment and by default in v1.0.0
- Disable storage account keys and use managed identities
  - Switch to optional user-assigned managed identity for all resources (e.g. `id-start-stop-solution`)
- Private endpoint support and VNet integration for function app
```hcl
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

resource "azurerm_storage_account" "storage" {
  account_kind                    = "Storage"
  account_replication_type        = "LRS"
  account_tier                    = "Standard"
  allow_nested_items_to_be_public = false
  location                        = azurerm_resource_group.this.location
  min_tls_version                 = "TLS1_2"
  name                            = var.storage_account_name != null ? var.storage_account_name : "sa${var.name}"
  resource_group_name             = azurerm_resource_group.this.name
  tags                            = local.solution_merged_tags
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
    AzureWebJobsStorage                   = "DefaultEndpointsProtocol=https;AccountName=${azurerm_storage_account.storage.name};AccountKey=${azurerm_storage_account.storage.primary_access_key}"
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.app_insights.connection_string
    APPINSIGHTS_INSTRUMENTATIONKEY        = azurerm_application_insights.app_insights.instrumentation_key
    FUNCTIONS_EXTENSION_VERSION           = "~4"
    WEBSITE_NODE_DEFAULT_VERSION          = "~10"
    "WEBSITE_CONTENTSHARE"                = var.function_app_name != null ? var.function_app_name : "fnc-${var.name}"
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

  tags = local.solution_merged_tags

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      dotnet_version = "v6.0"
    }

    ftps_state = "FtpsOnly"
  }
}

resource "azurerm_role_assignment" "fnc_contributor" {
  principal_id         = azurerm_windows_function_app.function_app.identity[0].principal_id
  scope                = format("/subscriptions/%s", data.azurerm_client_config.current.subscription_id)
  role_definition_name = "Contributor"
}

resource "time_sleep" "wait_120_seconds" {
  depends_on = [azurerm_role_assignment.fnc_contributor]

  create_duration = "120s"
}

resource "azurerm_logic_app_workflow" "logic_app_auto_stop" {
  depends_on          = [time_sleep.wait_120_seconds]
  enabled             = var.auto_stop_logic_app_enabled
  location            = azurerm_resource_group.this.location
  name                = var.auto_stop_logic_app_name != null ? var.auto_stop_logic_app_name : "ststv2_vms_AutoStop"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.solution_merged_tags
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
  tags                = local.solution_tags
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
  tags                = local.solution_tags
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
}

resource "azurerm_portal_dashboard" "dashboard" {
  dashboard_properties = <<DASHBOARD_PROPERTIES
{
  "lenses": {
    "0": {
      "order": 0,
      "parts": {
        "0": {
          "metadata": {
            "inputs": [],
            "settings": {
              "content": {
                "settings": {
                  "content": "This is your StartStop VMs dashboard.\\n\\nFor more information view [doc](https://github.com/microsoft/startstopv2-deployments/blob/main/README.md)\\n\\n**Deployment information**\\n\\u003e **Subscription :** CyberScot-Prd  \\n\\u003e **Resource Group :** ${azurerm_application_insights.app_insights.name}  \\n\\u003e **Application Insights :** ${azurerm_application_insights.app_insights.name}",
                  "markdownSource": 1,
                  "subtitle": "",
                  "title": "Welcome!"
                }
              },
              "type": "Extension/HubsExtension/PartType/MarkdownPart"
            },
            "position": {
              "colSpan": 3,
              "rowSpan": 4,
              "x": 0,
              "y": 0
            }
          }
        },
        "1": {
          "metadata": {
            "inputs": [
              {
                "name": "ComponentId",
                "value": {
                  "Name": "${azurerm_application_insights.app_insights.name}",
                  "ResourceGroup": "${azurerm_application_insights.app_insights.name}",
                  "ResourceId": "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${azurerm_application_insights.app_insights.name}/providers/Microsoft.Insights/components/${azurerm_application_insights.app_insights.name}",
                  "SubscriptionId": "${azurerm_application_insights.app_insights.name}"
                }
              },
              {
                "name": "Query",
                "value": "traces \\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\" and customDimensions.prop__Successful == true\\n| project      \\n    action = tostring(customDimensions.prop__ActionType),\\n    value = customDimensions.prop__value,\\n    timestamp\\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\\n"
              },
              {
                "name": "TimeRange",
                "value": "PT30M"
              },
              {
                "name": "Dimensions",
                "value": {
                  "aggregation": "Sum",
                  "splitBy": [
                    {
                      "name": "action",
                      "type": "string"
                    }
                  ],
                  "xAxis": {
                    "name": "timestamp",
                    "type": "datetime"
                  },
                  "yAxis": [
                    {
                      "name": "request_count",
                      "type": "real"
                    }
                  ]
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
                "isOptional": true,
                "name": "DashboardId"
              },
              {
                "isOptional": true,
                "name": "Scope"
              },
              {
                "isOptional": true,
                "name": "DraftRequestParameters"
              },
              {
                "isOptional": true,
                "name": "LegendOptions"
              },
              {
                "isOptional": true,
                "name": "IsQueryContainTimeRange"
              }
            ],
            "settings": {
              "content": {
                "LegendOptions": {
                  "isEnabled": true,
                  "position": "Bottom"
                },
                "Query": "traces \\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\" and customDimensions.prop__Successful == true\\n| project      \\n    action = tostring(customDimensions.prop__ActionType),\\n    value = customDimensions.prop__Value,\\n    timestamp\\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\\n\\n"
              }
            },
            "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart"
          },
          "position": {
            "colSpan": 5,
            "rowSpan": 4,
            "x": 3,
            "y": 0
          }
        },
        "2": {
          "metadata": {
            "inputs": [
              {
                "isOptional": true,
                "name": "resourceTypeMode",
                "value": "components"
              },
              {
                "isOptional": true,
                "name": "ComponentId",
                "value": {
                  "Name": "${azurerm_application_insights.app_insights.name}",
                  "ResourceGroup": "${azurerm_application_insights.app_insights.name}",
                  "ResourceId": "/subscriptions/${azurerm_application_insights.app_insights.name}/resourceGroups/${azurerm_application_insights.app_insights.name}/providers/Microsoft.Insights/components/${azurerm_application_insights.app_insights.name}",
                  "SubscriptionId": "${azurerm_application_insights.app_insights.name}"
                }
              },
              {
                "isOptional": true,
                "name": "Scope"
              },
              {
                "isOptional": true,
                "name": "PartId",
                "value": "1873282b-e618-432b-8147-bd0cfb34cf73"
              },
              {
                "isOptional": true,
                "name": "Version",
                "value": "1.0"
              },
              {
                "isOptional": true,
                "name": "TimeRange",
                "value": "PT30M"
              },
              {
                "isOptional": true,
                "name": "DashboardId"
              },
              {
                "isOptional": true,
                "name": "DraftRequestParameters"
              },
              {
                "isOptional": true,
                "name": "Query",
                "value": "traces \\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\" and customDimensions.prop__Successful == true\\n| project      \\n    action = tostring(customDimensions.prop__ActionType),\\n    value = customDimensions.prop__value,\\n    timestamp\\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\\n"
              },
              {
                "isOptional": true,
                "name": "ControlType",
                "value": "FrameControlChart"
              },
              {
                "isOptional": true,
                "name": "SpecificChart",
                "value": "UnstackedColumn"
              },
              {
                "isOptional": true,
                "name": "PartTitle",
                "value": "Successful Start and Stop Actions Taken"
              },
              {
                "isOptional": true,
                "name": "PartSubTitle",
                "value": "Total count of successful start and stop actions taken against your virtual machines by the StartStop service."
              },
              {
                "isOptional": true,
                "name": "Dimensions",
                "value": {
                  "aggregation": "Sum",
                  "splitBy": [
                    {
                      "name": "action",
                      "type": "string"
                    }
                  ],
                  "xAxis": {
                    "name": "timestamp",
                    "type": "datetime"
                  },
                  "yAxis": [
                    {
                      "name": "request_count",
                      "type": "real"
                    }
                  ]
                }
              },
              {
                "isOptional": true,
                "name": "LegendOptions"
              },
              {
                "isOptional": true,
                "name": "IsQueryContainTimeRange"
              }
            ],
            "partHeader": {
              "subtitle": "",
              "title": "Failed Start and Stop Actions Taken"
            },
            "settings": {
              "content": {
                "ControlType": "AnalyticsGrid",
                "LegendOptions": {
                  "isEnabled": true,
                  "position": "Bottom"
                },
                "Query": "traces \\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\" and customDimensions.prop__Successful == false\\n| project      \\n    action = tostring(customDimensions.prop__ActionType),\\n    value = customDimensions.prop__Value,\\n    timestamp\\n| summarize request_count=sum(toreal(value)) by action,bin(timestamp, 1h)\\n\\n"
              }
            },
            "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart"
          },
          "position": {
            "colSpan": 5,
            "rowSpan": 4,
            "x": 8,
            "y": 0
          }
        },
        "3": {
          "metadata": {
            "asset": {
              "idInputName": "ComponentId",
              "type": "ApplicationInsights"
            },
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
                  "Name": "${azurerm_application_insights.app_insights.name}",
                  "ResourceGroup": "${azurerm_application_insights.app_insights.name}",
                  "ResourceId": "/subscriptions/${azurerm_application_insights.app_insights.name}/resourceGroups/${azurerm_application_insights.app_insights.name}/providers/Microsoft.Insights/components/${azurerm_application_insights.app_insights.name}",
                  "SubscriptionId": "${azurerm_application_insights.app_insights.name}"
                }
              },
              {
                "name": "Query",
                "value": "traces\\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\"\\n| project      \\n  action = customDimensions.prop__ActionType,\\n  virtual_machine = customDimensions.prop__ResourceName,\\n  resource_group = customDimensions.prop__ResourceGroup,\\n  subscription_ID = customDimensions.prop__SubscriptionId,\\n  timestamp\\n| order by timestamp desc\\n"
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
                "isOptional": true,
                "name": "Dimensions"
              },
              {
                "isOptional": true,
                "name": "DashboardId"
              },
              {
                "isOptional": true,
                "name": "SpecificChart"
              },
              {
                "isOptional": true,
                "name": "Scope"
              },
              {
                "isOptional": true,
                "name": "DraftRequestParameters"
              },
              {
                "isOptional": true,
                "name": "LegendOptions"
              },
              {
                "isOptional": true,
                "name": "IsQueryContainTimeRange"
              }
            ],
            "settings": {},
            "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart"
          },
          "position": {
            "colSpan": 9,
            "rowSpan": 4,
            "x": 0,
            "y": 4
          }
        },
        "4": {
          "metadata": {
            "inputs": [
              {
                "isOptional": true,
                "name": "ComponentId",
                "value": {
                  "Name": "${azurerm_application_insights.app_insights.name}",
                  "ResourceGroup": "${azurerm_application_insights.app_insights.name}",
                  "ResourceId": "/subscriptions/${azurerm_application_insights.app_insights.name}/resourceGroups/${azurerm_application_insights.app_insights.name}/providers/Microsoft.Insights/components/${azurerm_application_insights.app_insights.name}",
                  "SubscriptionId": "${azurerm_application_insights.app_insights.name}"
                }
              },
              {
                "isOptional": true,
                "name": "Dimensions",
                "value": {
                  "aggregation": "Sum",
                  "splitBy": [],
                  "xAxis": {
                    "name": "action",
                    "type": "string"
                  },
                  "yAxis": [
                    {
                      "name": "request_count",
                      "type": "real"
                    }
                  ]
                }
              },
              {
                "isOptional": true,
                "name": "Query",
                "value": "traces\\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\" and customDimensions.prop__Successful == true\\n| project      \\n    action = tostring(customDimensions.prop__ActionType),\\n    value = toreal(customDimensions.prop__value),\\n    timestamp\\n| summarize request_count=sum(value) by action,bin(timestamp, 1h)\\n"
              },
              {
                "isOptional": true,
                "name": "PartTitle",
                "value": "Start \\u0026 Stop (%)"
              },
              {
                "isOptional": true,
                "name": "PartSubTitle",
                "value": "Total % count of start and stop action"
              },
              {
                "isOptional": true,
                "name": "PartId",
                "value": "08ad6984-455d-440c-9596-73760a4178c3"
              },
              {
                "isOptional": true,
                "name": "Version",
                "value": "1.0"
              },
              {
                "isOptional": true,
                "name": "resourceTypeMode",
                "value": "components"
              },
              {
                "isOptional": true,
                "name": "TimeRange",
                "value": "P30D"
              },
              {
                "isOptional": true,
                "name": "DashboardId"
              },
              {
                "isOptional": true,
                "name": "ControlType",
                "value": "FrameControlChart"
              },
              {
                "isOptional": true,
                "name": "SpecificChart",
                "value": "Donut"
              },
              {
                "isOptional": true,
                "name": "Scope"
              },
              {
                "isOptional": true,
                "name": "DraftRequestParameters"
              },
              {
                "isOptional": true,
                "name": "LegendOptions"
              },
              {
                "isOptional": true,
                "name": "IsQueryContainTimeRange"
              }
            ],
            "settings": {
              "content": {
                "LegendOptions": {
                  "isEnabled": true,
                  "position": "Bottom"
                },
                "Query": "traces\\n| where customDimensions.prop__Name == \\\"VmExecutionsAttempted\\\" and customDimensions.prop__Successful == true\\n| project      \\n    action = tostring(customDimensions.prop__ActionType),\\n    value = toreal(customDimensions.prop__Value),\\n    timestamp\\n| summarize request_count=sum(value) by action,bin(timestamp, 1h)\\n\\n"
              }
            },
            "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart"
          },
          "position": {
            "colSpan": 4,
            "rowSpan": 4,
            "x": 9,
            "y": 4
          }
        },
        "5": {
          "metadata": {
            "inputs": [
              {
                "name": "ComponentId",
                "value": {
                  "Name": "${azurerm_application_insights.app_insights.name}",
                  "ResourceGroup": "${azurerm_application_insights.app_insights.name}",
                  "ResourceId": "/subscriptions/${azurerm_application_insights.app_insights.name}/resourceGroups/${azurerm_application_insights.app_insights.name}/providers/Microsoft.Insights/components/${azurerm_application_insights.app_insights.name}",
                  "SubscriptionId": "${azurerm_application_insights.app_insights.name}"
                }
              },
              {
                "name": "Query",
                "value": "(traces\\n| where customDimensions.prop__Name == \\\"NoPiiScheduleRequests\\\" and tobool(customDimensions.prop__Sequenced)\\n| project scenario = \\\"Sequenced\\\",      value = toreal(customDimensions.prop__value),      timestamp)\\n| union\\n(traces\\n| where customDimensions.prop__Name == \\\"NoPiiScheduleRequests\\\" and tobool(customDimensions.prop__Sequenced) == false\\n| project scenario = \\\"Scheduled\\\",      value = toreal(customDimensions.prop__value),      timestamp)\\n| union\\n(traces\\n| where customDimensions.prop__Name == \\\"NoPiiAutoStopRequests\\\"\\n| project scenario = \\\"AutoStop\\\",      value = toreal(customDimensions.prop__value),      timestamp)\\n| summarize request_count=sum(value) by scenario,bin(timestamp, 15m)\\n"
              },
              {
                "name": "TimeRange",
                "value": "PT1H"
              },
              {
                "name": "Dimensions",
                "value": {
                  "aggregation": "Sum",
                  "splitBy": [
                    {
                      "name": "scenario",
                      "type": "string"
                    }
                  ],
                  "xAxis": {
                    "name": "timestamp",
                    "type": "datetime"
                  },
                  "yAxis": [
                    {
                      "name": "request_count",
                      "type": "real"
                    }
                  ]
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
                "isOptional": true,
                "name": "DashboardId"
              },
              {
                "isOptional": true,
                "name": "Scope"
              },
              {
                "isOptional": true,
                "name": "DraftRequestParameters"
              },
              {
                "isOptional": true,
                "name": "LegendOptions"
              },
              {
                "isOptional": true,
                "name": "IsQueryContainTimeRange"
              }
            ],
            "settings": {
              "content": {
                "LegendOptions": {
                  "isEnabled": true,
                  "position": "Bottom"
                },
                "Query": "(traces\\n| where customDimensions.prop__Name == \\\"NoPiiScheduleRequests\\\" and tobool(customDimensions.prop__Sequenced)\\n| project scenario = \\\"Sequenced\\\",      value = toreal(customDimensions.prop__Value),      timestamp)\\n| union\\n(traces\\n| where customDimensions.prop__Name == \\\"NoPiiScheduleRequests\\\" and tobool(customDimensions.prop__Sequenced) == false\\n| project scenario = \\\"Scheduled\\\",      value = toreal(customDimensions.prop__Value),      timestamp)\\n| union\\n(traces\\n| where customDimensions.prop__Name == \\\"NoPiiAutoStopRequests\\\"\\n| project scenario = \\\"AutoStop\\\",      value = toreal(customDimensions.prop__Value),      timestamp)\\n| summarize request_count=sum(value) by scenario,bin(timestamp, 15m)\\n\\n"
              }
            },
            "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart"
          },
          "position": {
            "colSpan": 4,
            "rowSpan": 4,
            "x": 13,
            "y": 4
          }
        },
        "6": {
          "metadata": {
            "inputs": [
              {
                "name": "ComponentId",
                "value": {
                  "Name": "${azurerm_application_insights.app_insights.name}",
                  "ResourceGroup": "${azurerm_application_insights.app_insights.name}",
                  "ResourceId": "/subscriptions/${azurerm_application_insights.app_insights.name}/resourceGroups/${azurerm_resource_group.this.name}/providers/Microsoft.Insights/components/${azurerm_application_insights.app_insights.name}",
                  "SubscriptionId": "${azurerm_application_insights.app_insights.name}"
                }
              },
              {
                "name": "Query",
                "value": "traces\\n| where customDimensions.prop__Name == \\\"NoPiiScheduleRequests\\\"\\n| project      \\n    scenario = tostring(customDimensions.prop__Scenario),\\n    value = toreal(customDimensions.prop__value),\\n    timestamp\\n| summarize request_count=sum(value) by scenario,bin(timestamp, 1h)\\n"
              },
              {
                "name": "TimeRange",
                "value": "PT1H"
              },
              {
                "name": "Dimensions",
                "value": {
                  "aggregation": "Sum",
                  "splitBy": [
                    {
                      "name": "scenario",
                      "type": "string"
                    }
                  ],
                  "xAxis": {
                    "name": "timestamp",
                    "type": "datetime"
                  },
                  "yAxis": [
                    {
                      "name": "request_count",
                      "type": "real"
                    }
                  ]
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
                "isOptional": true,
                "name": "DashboardId"
              },
              {
                "isOptional": true,
                "name": "Scope"
              },
              {
                "isOptional": true,
                "name": "DraftRequestParameters"
              },
              {
                "isOptional": true,
                "name": "LegendOptions"
              },
              {
                "isOptional": true,
                "name": "IsQueryContainTimeRange"
              }
            ],
            "settings": {
              "content": {
                "LegendOptions": {
                  "isEnabled": true,
                  "position": "Bottom"
                },
                "Query": "traces\\n| where customDimensions.prop__Name == \\\"NoPiiScheduleRequests\\\"\\n| project      \\n    scenario = tostring(customDimensions.prop__Scenario),\\n    value = toreal(customDimensions.prop__Value),\\n    timestamp\\n| summarize request_count=sum(value) by scenario,bin(timestamp, 1h)\\n\\n"
              }
            },
            "type": "Extension/Microsoft_OperationsManagementSuite_Workspace/PartType/LogsDashboardPart"
          },
          "position": {
            "colSpan": 4,
            "rowSpan": 4,
            "x": 17,
            "y": 4
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

```
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | n/a |
| <a name="provider_time"></a> [time](#provider\_time) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_application_insights.app_insights](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights) | resource |
| [azurerm_log_analytics_workspace.law](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/log_analytics_workspace) | resource |
| [azurerm_logic_app_action_custom.auto_stop_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.auto_stop_success_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.auto_stop_terminate](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.scheduled_start_start_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.scheduled_start_success_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.scheduled_start_terminate](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.scheduled_stop_failed_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.scheduled_stop_stop_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.scheduled_stop_succeeded_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.sequenced_start_failed_action](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.sequenced_start_start_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.sequenced_start_success_action](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.sequenced_stop_stop_action](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.sequenced_stop_success_action](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_action_custom.sequenced_stop_termination_function](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_action_custom) | resource |
| [azurerm_logic_app_trigger_recurrence.auto_stop_recurrence_trigger](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_trigger_recurrence) | resource |
| [azurerm_logic_app_trigger_recurrence.scheduled_start_daily_trigger](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_trigger_recurrence) | resource |
| [azurerm_logic_app_trigger_recurrence.scheduled_stop_daily_recurrence](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_trigger_recurrence) | resource |
| [azurerm_logic_app_trigger_recurrence.sequenced_start_daily_trigger](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_trigger_recurrence) | resource |
| [azurerm_logic_app_trigger_recurrence.sequenced_stop_daily_trigger](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_trigger_recurrence) | resource |
| [azurerm_logic_app_workflow.logic_app_auto_stop](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_workflow) | resource |
| [azurerm_logic_app_workflow.logic_app_scheduled_start](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_workflow) | resource |
| [azurerm_logic_app_workflow.logic_app_scheduled_stop](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_workflow) | resource |
| [azurerm_logic_app_workflow.logic_app_sequenced_start](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_workflow) | resource |
| [azurerm_logic_app_workflow.logic_app_sequenced_stop](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/logic_app_workflow) | resource |
| [azurerm_management_lock.rg_lock](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/management_lock) | resource |
| [azurerm_monitor_action_group.app_insights_ag](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_action_group) | resource |
| [azurerm_monitor_action_group.notification_group_ag](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_action_group) | resource |
| [azurerm_monitor_scheduled_query_rules_alert_v2.auto_stop_query_alert_rules](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_scheduled_query_rules_alert_v2) | resource |
| [azurerm_monitor_scheduled_query_rules_alert_v2.scheduled_query_alert_rules](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_scheduled_query_rules_alert_v2) | resource |
| [azurerm_monitor_scheduled_query_rules_alert_v2.sequenced_query_alert_rules](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_scheduled_query_rules_alert_v2) | resource |
| [azurerm_monitor_smart_detector_alert_rule.app_insights_anomalies_detector](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_smart_detector_alert_rule) | resource |
| [azurerm_portal_dashboard.dashboard](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/portal_dashboard) | resource |
| [azurerm_resource_group.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) | resource |
| [azurerm_role_assignment.fnc_contributor](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_service_plan.fnc_asp](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/service_plan) | resource |
| [azurerm_storage_account.storage](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account) | resource |
| [azurerm_storage_account_network_rules.storage_rules](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules) | resource |
| [azurerm_storage_container.web_jobs_hosts](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container) | resource |
| [azurerm_storage_container.web_jobs_secrets](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container) | resource |
| [azurerm_storage_queue.auto_update_request_queue](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_queue) | resource |
| [azurerm_storage_queue.create_alert_request](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_queue) | resource |
| [azurerm_storage_queue.execution_request](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_queue) | resource |
| [azurerm_storage_queue.orchestration_request](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_queue) | resource |
| [azurerm_storage_queue.savings_request_queue](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_queue) | resource |
| [azurerm_storage_table.auto_update_request_details_store_table](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_table) | resource |
| [azurerm_storage_table.requests_store_stable](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_table) | resource |
| [azurerm_storage_table.subscription_requests_store_stable](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_table) | resource |
| [azurerm_windows_function_app.function_app](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_function_app) | resource |
| [time_sleep.wait_120_seconds](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [azurerm_client_config.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) | data source |
| [azurerm_log_analytics_workspace.read_created_law](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/log_analytics_workspace) | data source |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_all_solution_ips"></a> [all\_solution\_ips](#output\_all\_solution\_ips) | All the public IPs from function apps and logic apps made by this solution |
| <a name="output_app_insights_action_group_id"></a> [app\_insights\_action\_group\_id](#output\_app\_insights\_action\_group\_id) | The ID of the Application Insights Action Group. |
| <a name="output_app_insights_action_group_name"></a> [app\_insights\_action\_group\_name](#output\_app\_insights\_action\_group\_name) | The name of the Application Insights Action Group. |
| <a name="output_app_insights_anomalies_detector_id"></a> [app\_insights\_anomalies\_detector\_id](#output\_app\_insights\_anomalies\_detector\_id) | The ID of the Application Insights Anomalies Detector. |
| <a name="output_app_insights_anomalies_detector_name"></a> [app\_insights\_anomalies\_detector\_name](#output\_app\_insights\_anomalies\_detector\_name) | The name of the Application Insights Anomalies Detector. |
| <a name="output_app_insights_id"></a> [app\_insights\_id](#output\_app\_insights\_id) | The ID of the Application Insights. |
| <a name="output_app_insights_key"></a> [app\_insights\_key](#output\_app\_insights\_key) | The Instrumentation Key of the Application Insights. |
| <a name="output_app_insights_name"></a> [app\_insights\_name](#output\_app\_insights\_name) | The name of the Application Insights. |
| <a name="output_auto_stop_function_id"></a> [auto\_stop\_function\_id](#output\_auto\_stop\_function\_id) | The ID of the Logic App Custom Action for Auto Stop Function. |
| <a name="output_auto_stop_logic_app_ips"></a> [auto\_stop\_logic\_app\_ips](#output\_auto\_stop\_logic\_app\_ips) | IP Addresses for the Auto Stop Logic App |
| <a name="output_auto_stop_query_alert_rules_id"></a> [auto\_stop\_query\_alert\_rules\_id](#output\_auto\_stop\_query\_alert\_rules\_id) | The ID of the Auto Stop Query Alert Rules. |
| <a name="output_auto_stop_query_alert_rules_name"></a> [auto\_stop\_query\_alert\_rules\_name](#output\_auto\_stop\_query\_alert\_rules\_name) | The name of the Auto Stop Query Alert Rules. |
| <a name="output_auto_stop_recurrence_trigger_id"></a> [auto\_stop\_recurrence\_trigger\_id](#output\_auto\_stop\_recurrence\_trigger\_id) | The ID of the Logic App Recurrence Trigger for Auto Stop. |
| <a name="output_auto_stop_recurrence_trigger_name"></a> [auto\_stop\_recurrence\_trigger\_name](#output\_auto\_stop\_recurrence\_trigger\_name) | The name of the Logic App Recurrence Trigger for Auto Stop. |
| <a name="output_auto_stop_success_function_id"></a> [auto\_stop\_success\_function\_id](#output\_auto\_stop\_success\_function\_id) | The ID of the Logic App Custom Action for Auto Stop Success Function. |
| <a name="output_auto_stop_terminate_id"></a> [auto\_stop\_terminate\_id](#output\_auto\_stop\_terminate\_id) | The ID of the Logic App Custom Action for Auto Stop Terminate. |
| <a name="output_auto_update_request_details_store_table_name"></a> [auto\_update\_request\_details\_store\_table\_name](#output\_auto\_update\_request\_details\_store\_table\_name) | The name of the Auto Update Request Details Store Table. |
| <a name="output_auto_update_request_queue_name"></a> [auto\_update\_request\_queue\_name](#output\_auto\_update\_request\_queue\_name) | The name of the Auto Update Request Queue. |
| <a name="output_create_alert_request_queue_name"></a> [create\_alert\_request\_queue\_name](#output\_create\_alert\_request\_queue\_name) | The name of the Create Alert Request Queue. |
| <a name="output_dashboard_id"></a> [dashboard\_id](#output\_dashboard\_id) | The id of the dashboard |
| <a name="output_dashboard_name"></a> [dashboard\_name](#output\_dashboard\_name) | The name of the dashboard |
| <a name="output_execution_request_queue_name"></a> [execution\_request\_queue\_name](#output\_execution\_request\_queue\_name) | The name of the Execution Request Queue. |
| <a name="output_function_app_id"></a> [function\_app\_id](#output\_function\_app\_id) | The ID of the Windows Function App. |
| <a name="output_function_app_name"></a> [function\_app\_name](#output\_function\_app\_name) | The name of the Windows Function App. |
| <a name="output_function_app_principal_id"></a> [function\_app\_principal\_id](#output\_function\_app\_principal\_id) | The Principal ID of the Windows Function App's System Assigned Identity. |
| <a name="output_function_outbound_ips"></a> [function\_outbound\_ips](#output\_function\_outbound\_ips) | The outbound IPs of the Windows Function App. |
| <a name="output_function_outbound_ips_list"></a> [function\_outbound\_ips\_list](#output\_function\_outbound\_ips\_list) | The outbound IPs of the Windows Function App in list format. |
| <a name="output_function_possible_outbound_ips"></a> [function\_possible\_outbound\_ips](#output\_function\_possible\_outbound\_ips) | The possible\_outbound IPs of the Windows Function App. |
| <a name="output_function_possible_outbound_ips_list"></a> [function\_possible\_outbound\_ips\_list](#output\_function\_possible\_outbound\_ips\_list) | The possible\_outbound IPs of the Windows Function App in list format. |
| <a name="output_law_id"></a> [law\_id](#output\_law\_id) | The ID of the Log Analytics Workspace. |
| <a name="output_law_name"></a> [law\_name](#output\_law\_name) | The name of the Log Analytics Workspace. |
| <a name="output_logic_app_auto_stop_id"></a> [logic\_app\_auto\_stop\_id](#output\_logic\_app\_auto\_stop\_id) | The ID of the Logic App Workflow for Auto Stop. |
| <a name="output_logic_app_auto_stop_name"></a> [logic\_app\_auto\_stop\_name](#output\_logic\_app\_auto\_stop\_name) | The name of the Logic App Workflow for Auto Stop. |
| <a name="output_logic_app_scheduled_start_id"></a> [logic\_app\_scheduled\_start\_id](#output\_logic\_app\_scheduled\_start\_id) | The ID of the Logic App Workflow for Scheduled Start. |
| <a name="output_logic_app_scheduled_start_name"></a> [logic\_app\_scheduled\_start\_name](#output\_logic\_app\_scheduled\_start\_name) | The name of the Logic App Workflow for Scheduled Start. |
| <a name="output_logic_app_scheduled_stop_id"></a> [logic\_app\_scheduled\_stop\_id](#output\_logic\_app\_scheduled\_stop\_id) | The ID of the Logic App Workflow for Scheduled Stop. |
| <a name="output_logic_app_scheduled_stop_name"></a> [logic\_app\_scheduled\_stop\_name](#output\_logic\_app\_scheduled\_stop\_name) | The name of the Logic App Workflow for Scheduled Stop. |
| <a name="output_logic_app_sequenced_start_id"></a> [logic\_app\_sequenced\_start\_id](#output\_logic\_app\_sequenced\_start\_id) | The ID of the Logic App Workflow for Sequenced Start. |
| <a name="output_logic_app_sequenced_start_name"></a> [logic\_app\_sequenced\_start\_name](#output\_logic\_app\_sequenced\_start\_name) | The name of the Logic App Workflow for Sequenced Start. |
| <a name="output_logic_app_sequenced_stop_id"></a> [logic\_app\_sequenced\_stop\_id](#output\_logic\_app\_sequenced\_stop\_id) | The ID of the Logic App Workflow for Sequenced Stop. |
| <a name="output_logic_app_sequenced_stop_name"></a> [logic\_app\_sequenced\_stop\_name](#output\_logic\_app\_sequenced\_stop\_name) | The name of the Logic App Workflow for Sequenced Stop. |
| <a name="output_notification_action_group_id"></a> [notification\_action\_group\_id](#output\_notification\_action\_group\_id) | The ID of the Notification Action Group. |
| <a name="output_notification_action_group_name"></a> [notification\_action\_group\_name](#output\_notification\_action\_group\_name) | The name of the Notification Action Group. |
| <a name="output_orchestration_request_queue_name"></a> [orchestration\_request\_queue\_name](#output\_orchestration\_request\_queue\_name) | The name of the Orchestration Request Queue. |
| <a name="output_requests_store_table_name"></a> [requests\_store\_table\_name](#output\_requests\_store\_table\_name) | The name of the Requests Store Table. |
| <a name="output_rg_id"></a> [rg\_id](#output\_rg\_id) | The id of the resource group |
| <a name="output_rg_location"></a> [rg\_location](#output\_rg\_location) | The location of the resource group |
| <a name="output_rg_name"></a> [rg\_name](#output\_rg\_name) | The name of the resource group |
| <a name="output_rg_tags"></a> [rg\_tags](#output\_rg\_tags) | The tags of the resource group |
| <a name="output_role_assignment_id"></a> [role\_assignment\_id](#output\_role\_assignment\_id) | The ID of the Role Assignment. |
| <a name="output_role_assignment_principal_id"></a> [role\_assignment\_principal\_id](#output\_role\_assignment\_principal\_id) | The Principal ID associated with the Role Assignment. |
| <a name="output_role_assignment_role_definition_name"></a> [role\_assignment\_role\_definition\_name](#output\_role\_assignment\_role\_definition\_name) | The Role Definition Name associated with the Role Assignment. |
| <a name="output_savings_request_queue_name"></a> [savings\_request\_queue\_name](#output\_savings\_request\_queue\_name) | The name of the Savings Request Queue. |
| <a name="output_scheduled_query_alert_rules_id"></a> [scheduled\_query\_alert\_rules\_id](#output\_scheduled\_query\_alert\_rules\_id) | The ID of the Scheduled Query Alert Rules. |
| <a name="output_scheduled_query_alert_rules_name"></a> [scheduled\_query\_alert\_rules\_name](#output\_scheduled\_query\_alert\_rules\_name) | The name of the Scheduled Query Alert Rules. |
| <a name="output_scheduled_start_daily_trigger_id"></a> [scheduled\_start\_daily\_trigger\_id](#output\_scheduled\_start\_daily\_trigger\_id) | The ID of the Logic App Recurrence Trigger for Scheduled Start. |
| <a name="output_scheduled_start_daily_trigger_name"></a> [scheduled\_start\_daily\_trigger\_name](#output\_scheduled\_start\_daily\_trigger\_name) | The name of the Logic App Recurrence Trigger for Scheduled Start. |
| <a name="output_scheduled_start_logic_app_ips"></a> [scheduled\_start\_logic\_app\_ips](#output\_scheduled\_start\_logic\_app\_ips) | IP Addresses for the Scheduled Start Logic App |
| <a name="output_scheduled_start_start_function_id"></a> [scheduled\_start\_start\_function\_id](#output\_scheduled\_start\_start\_function\_id) | The ID of the Logic App Custom Action for Scheduled Start Start Function. |
| <a name="output_scheduled_start_success_function_id"></a> [scheduled\_start\_success\_function\_id](#output\_scheduled\_start\_success\_function\_id) | The ID of the Logic App Custom Action for Scheduled Start Success Function. |
| <a name="output_scheduled_start_terminate_id"></a> [scheduled\_start\_terminate\_id](#output\_scheduled\_start\_terminate\_id) | The ID of the Logic App Custom Action for Scheduled Start Terminate. |
| <a name="output_scheduled_stop_daily_recurrence_id"></a> [scheduled\_stop\_daily\_recurrence\_id](#output\_scheduled\_stop\_daily\_recurrence\_id) | The ID of the Logic App Recurrence Trigger for Scheduled Stop. |
| <a name="output_scheduled_stop_daily_recurrence_name"></a> [scheduled\_stop\_daily\_recurrence\_name](#output\_scheduled\_stop\_daily\_recurrence\_name) | The name of the Logic App Recurrence Trigger for Scheduled Stop. |
| <a name="output_scheduled_stop_failed_function_id"></a> [scheduled\_stop\_failed\_function\_id](#output\_scheduled\_stop\_failed\_function\_id) | The ID of the Logic App Custom Action for Scheduled Stop Failed Function. |
| <a name="output_scheduled_stop_logic_app_ips"></a> [scheduled\_stop\_logic\_app\_ips](#output\_scheduled\_stop\_logic\_app\_ips) | IP Addresses for the Scheduled Stop Logic App |
| <a name="output_scheduled_stop_stop_function_id"></a> [scheduled\_stop\_stop\_function\_id](#output\_scheduled\_stop\_stop\_function\_id) | The ID of the Logic App Custom Action for Scheduled Stop Stop Function. |
| <a name="output_scheduled_stop_succeeded_function_id"></a> [scheduled\_stop\_succeeded\_function\_id](#output\_scheduled\_stop\_succeeded\_function\_id) | The ID of the Logic App Custom Action for Scheduled Stop Succeeded Function. |
| <a name="output_sequenced_start_daily_trigger_id"></a> [sequenced\_start\_daily\_trigger\_id](#output\_sequenced\_start\_daily\_trigger\_id) | The ID of the Logic App Recurrence Trigger for Sequenced Start. |
| <a name="output_sequenced_start_daily_trigger_name"></a> [sequenced\_start\_daily\_trigger\_name](#output\_sequenced\_start\_daily\_trigger\_name) | The name of the Logic App Recurrence Trigger for Sequenced Start. |
| <a name="output_sequenced_start_failed_action_id"></a> [sequenced\_start\_failed\_action\_id](#output\_sequenced\_start\_failed\_action\_id) | The ID of the Logic App Custom Action for Sequenced Start Failed Action. |
| <a name="output_sequenced_start_logic_app_ips"></a> [sequenced\_start\_logic\_app\_ips](#output\_sequenced\_start\_logic\_app\_ips) | IP Addresses for the Sequenced Start Logic App |
| <a name="output_sequenced_start_start_function_id"></a> [sequenced\_start\_start\_function\_id](#output\_sequenced\_start\_start\_function\_id) | The ID of the Logic App Custom Action for Sequenced Start Start Function. |
| <a name="output_sequenced_start_success_action_id"></a> [sequenced\_start\_success\_action\_id](#output\_sequenced\_start\_success\_action\_id) | The ID of the Logic App Custom Action for Sequenced Start Success Action. |
| <a name="output_sequenced_stop_daily_trigger_id"></a> [sequenced\_stop\_daily\_trigger\_id](#output\_sequenced\_stop\_daily\_trigger\_id) | The ID of the Logic App Recurrence Trigger for Sequenced Stop. |
| <a name="output_sequenced_stop_daily_trigger_name"></a> [sequenced\_stop\_daily\_trigger\_name](#output\_sequenced\_stop\_daily\_trigger\_name) | The name of the Logic App Recurrence Trigger for Sequenced Stop. |
| <a name="output_sequenced_stop_logic_app_ips"></a> [sequenced\_stop\_logic\_app\_ips](#output\_sequenced\_stop\_logic\_app\_ips) | IP Addresses for the Sequenced Stop Logic App |
| <a name="output_sequenced_stop_stop_action_id"></a> [sequenced\_stop\_stop\_action\_id](#output\_sequenced\_stop\_stop\_action\_id) | The ID of the Logic App Custom Action for Sequenced Stop Action. |
| <a name="output_sequenced_stop_success_action_id"></a> [sequenced\_stop\_success\_action\_id](#output\_sequenced\_stop\_success\_action\_id) | The ID of the Logic App Custom Action for Sequenced Stop Success Action. |
| <a name="output_sequenced_stop_termination_function_id"></a> [sequenced\_stop\_termination\_function\_id](#output\_sequenced\_stop\_termination\_function\_id) | The ID of the Logic App Custom Action for Sequenced Stop Termination Function. |
| <a name="output_service_plan_id"></a> [service\_plan\_id](#output\_service\_plan\_id) | The ID of the Service Plan. |
| <a name="output_service_plan_name"></a> [service\_plan\_name](#output\_service\_plan\_name) | The name of the Service Plan. |
| <a name="output_storage_account_id"></a> [storage\_account\_id](#output\_storage\_account\_id) | The ID of the Storage Account. |
| <a name="output_storage_account_name"></a> [storage\_account\_name](#output\_storage\_account\_name) | The name of the Storage Account. |
| <a name="output_subscription_requests_store_table_name"></a> [subscription\_requests\_store\_table\_name](#output\_subscription\_requests\_store\_table\_name) | The name of the Subscription Requests Store Table. |
| <a name="output_web_jobs_hosts_container_name"></a> [web\_jobs\_hosts\_container\_name](#output\_web\_jobs\_hosts\_container\_name) | The name of the Web Jobs Hosts Storage Container. |
| <a name="output_web_jobs_secrets_container_name"></a> [web\_jobs\_secrets\_container\_name](#output\_web\_jobs\_secrets\_container\_name) | The name of the Web Jobs Secrets Storage Container. |
