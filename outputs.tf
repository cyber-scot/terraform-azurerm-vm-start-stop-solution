output "all_solution_ips" {
  value       = local.all_solution_ips
  description = "All the public IPs from function apps and logic apps made by this solution"
}

output "app_insights_action_group_id" {
  value       = azurerm_monitor_action_group.app_insights_ag.id
  description = "The ID of the Application Insights Action Group."
}

output "app_insights_action_group_name" {
  value       = azurerm_monitor_action_group.app_insights_ag.name
  description = "The name of the Application Insights Action Group."
}

output "app_insights_anomalies_detector_id" {
  value       = azurerm_monitor_smart_detector_alert_rule.app_insights_anomalies_detector.id
  description = "The ID of the Application Insights Anomalies Detector."
}

output "app_insights_anomalies_detector_name" {
  value       = azurerm_monitor_smart_detector_alert_rule.app_insights_anomalies_detector.name
  description = "The name of the Application Insights Anomalies Detector."
}

output "app_insights_id" {
  value       = azurerm_application_insights.app_insights.id
  description = "The ID of the Application Insights."
}

output "app_insights_key" {
  value       = azurerm_application_insights.app_insights.instrumentation_key
  description = "The Instrumentation Key of the Application Insights."
}

output "app_insights_name" {
  value       = azurerm_application_insights.app_insights.name
  description = "The name of the Application Insights."
}

output "auto_stop_function_id" {
  value       = azurerm_logic_app_action_custom.auto_stop_function.id
  description = "The ID of the Logic App Custom Action for Auto Stop Function."
}

output "auto_stop_logic_app_ips" {
  value = toset(concat(
    azurerm_logic_app_workflow.logic_app_auto_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_auto_stop.workflow_endpoint_ip_addresses
  ))
  description = "IP Addresses for the Auto Stop Logic App"
}

output "auto_stop_query_alert_rules_id" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.auto_stop_query_alert_rules.id
  description = "The ID of the Auto Stop Query Alert Rules."
}

output "auto_stop_query_alert_rules_name" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.auto_stop_query_alert_rules.name
  description = "The name of the Auto Stop Query Alert Rules."
}

output "auto_stop_recurrence_trigger_id" {
  value       = azurerm_logic_app_trigger_recurrence.auto_stop_recurrence_trigger.id
  description = "The ID of the Logic App Recurrence Trigger for Auto Stop."
}

output "auto_stop_recurrence_trigger_name" {
  value       = azurerm_logic_app_trigger_recurrence.auto_stop_recurrence_trigger.name
  description = "The name of the Logic App Recurrence Trigger for Auto Stop."
}

output "auto_stop_success_function_id" {
  value       = azurerm_logic_app_action_custom.auto_stop_success_function.id
  description = "The ID of the Logic App Custom Action for Auto Stop Success Function."
}

output "auto_stop_terminate_id" {
  value       = azurerm_logic_app_action_custom.auto_stop_terminate.id
  description = "The ID of the Logic App Custom Action for Auto Stop Terminate."
}

output "auto_update_request_details_store_table_name" {
  value       = azurerm_storage_table.auto_update_request_details_store_table.name
  description = "The name of the Auto Update Request Details Store Table."
}

output "auto_update_request_queue_name" {
  value       = azurerm_storage_queue.auto_update_request_queue.name
  description = "The name of the Auto Update Request Queue."
}

output "create_alert_request_queue_name" {
  value       = azurerm_storage_queue.create_alert_request.name
  description = "The name of the Create Alert Request Queue."
}

output "dashboard_id" {
  value       = azurerm_portal_dashboard.dashboard.id
  description = "The id of the dashboard"
}

output "dashboard_name" {
  value       = azurerm_portal_dashboard.dashboard.name
  description = "The name of the dashboard"
}

output "execution_request_queue_name" {
  value       = azurerm_storage_queue.execution_request.name
  description = "The name of the Execution Request Queue."
}

output "function_app_id" {
  value       = azurerm_windows_function_app.function_app.id
  description = "The ID of the Windows Function App."
}

output "function_app_name" {
  value       = azurerm_windows_function_app.function_app.name
  description = "The name of the Windows Function App."
}

output "function_app_principal_id" {
  value       = azurerm_windows_function_app.function_app.identity[0].principal_id
  description = "The Principal ID of the Windows Function App's System Assigned Identity."
}

output "function_outbound_ips" {
  value       = azurerm_windows_function_app.function_app.outbound_ip_addresses
  description = "The outbound IPs of the Windows Function App."
}

output "function_outbound_ips_list" {
  value       = azurerm_windows_function_app.function_app.outbound_ip_address_list
  description = "The outbound IPs of the Windows Function App in list format."
}

output "function_possible_outbound_ips" {
  value       = azurerm_windows_function_app.function_app.possible_outbound_ip_addresses
  description = "The possible_outbound IPs of the Windows Function App."
}

output "function_possible_outbound_ips_list" {
  value       = azurerm_windows_function_app.function_app.possible_outbound_ip_address_list
  description = "The possible_outbound IPs of the Windows Function App in list format."
}

output "law_id" {
  value       = length(azurerm_log_analytics_workspace.law) > 0 ? azurerm_log_analytics_workspace.law[0].id : null
  description = "The ID of the Log Analytics Workspace."
}

output "law_name" {
  value       = length(azurerm_log_analytics_workspace.law) > 0 ? azurerm_log_analytics_workspace.law[0].name : null
  description = "The name of the Log Analytics Workspace."
}

output "logic_app_auto_stop_id" {
  value       = azurerm_logic_app_workflow.logic_app_auto_stop.id
  description = "The ID of the Logic App Workflow for Auto Stop."
}

output "logic_app_auto_stop_name" {
  value       = azurerm_logic_app_workflow.logic_app_auto_stop.name
  description = "The name of the Logic App Workflow for Auto Stop."
}

output "logic_app_scheduled_start_id" {
  value       = azurerm_logic_app_workflow.logic_app_scheduled_start.id
  description = "The ID of the Logic App Workflow for Scheduled Start."
}

output "logic_app_scheduled_start_name" {
  value       = azurerm_logic_app_workflow.logic_app_scheduled_start.name
  description = "The name of the Logic App Workflow for Scheduled Start."
}

output "logic_app_scheduled_stop_id" {
  value       = azurerm_logic_app_workflow.logic_app_scheduled_stop.id
  description = "The ID of the Logic App Workflow for Scheduled Stop."
}

output "logic_app_scheduled_stop_name" {
  value       = azurerm_logic_app_workflow.logic_app_scheduled_stop.name
  description = "The name of the Logic App Workflow for Scheduled Stop."
}

output "logic_app_sequenced_start_id" {
  value       = azurerm_logic_app_workflow.logic_app_sequenced_start.id
  description = "The ID of the Logic App Workflow for Sequenced Start."
}

output "logic_app_sequenced_start_name" {
  value       = azurerm_logic_app_workflow.logic_app_sequenced_start.name
  description = "The name of the Logic App Workflow for Sequenced Start."
}

output "logic_app_sequenced_stop_id" {
  value       = azurerm_logic_app_workflow.logic_app_sequenced_stop.id
  description = "The ID of the Logic App Workflow for Sequenced Stop."
}

output "logic_app_sequenced_stop_name" {
  value       = azurerm_logic_app_workflow.logic_app_sequenced_stop.name
  description = "The name of the Logic App Workflow for Sequenced Stop."
}

output "notification_action_group_id" {
  value       = azurerm_monitor_action_group.notification_group_ag.id
  description = "The ID of the Notification Action Group."
}

output "notification_action_group_name" {
  value       = azurerm_monitor_action_group.notification_group_ag.name
  description = "The name of the Notification Action Group."
}

output "orchestration_request_queue_name" {
  value       = azurerm_storage_queue.orchestration_request.name
  description = "The name of the Orchestration Request Queue."
}

output "requests_store_table_name" {
  value       = azurerm_storage_table.requests_store_stable.name
  description = "The name of the Requests Store Table."
}

output "rg_id" {
  description = "The id of the resource group"
  value       = azurerm_resource_group.this.id
}

output "rg_location" {
  description = "The location of the resource group"
  value       = azurerm_resource_group.this.location
}

output "rg_name" {
  description = "The name of the resource group"
  value       = azurerm_resource_group.this.name
}

output "rg_tags" {
  description = "The tags of the resource group"
  value       = azurerm_resource_group.this.tags
}

output "role_assignment_id" {
  value       = azurerm_role_assignment.id_contributor.id
  description = "The ID of the Role Assignment."
}

output "role_assignment_principal_id" {
  value       = azurerm_role_assignment.id_contributor.principal_id
  description = "The Principal ID associated with the Role Assignment."
}

output "role_assignment_role_definition_name" {
  value       = azurerm_role_assignment.id_contributor.role_definition_name
  description = "The Role Definition Name associated with the Role Assignment."
}

output "savings_request_queue_name" {
  value       = azurerm_storage_queue.savings_request_queue.name
  description = "The name of the Savings Request Queue."
}

output "scheduled_query_alert_rules_id" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.scheduled_query_alert_rules.id
  description = "The ID of the Scheduled Query Alert Rules."
}

output "scheduled_query_alert_rules_name" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.scheduled_query_alert_rules.name
  description = "The name of the Scheduled Query Alert Rules."
}

output "scheduled_start_daily_trigger_id" {
  value       = azurerm_logic_app_trigger_recurrence.scheduled_start_daily_trigger.id
  description = "The ID of the Logic App Recurrence Trigger for Scheduled Start."
}

output "scheduled_start_daily_trigger_name" {
  value       = azurerm_logic_app_trigger_recurrence.scheduled_start_daily_trigger.name
  description = "The name of the Logic App Recurrence Trigger for Scheduled Start."
}

output "scheduled_start_logic_app_ips" {
  value = toset(concat(
    azurerm_logic_app_workflow.logic_app_scheduled_start.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_start.workflow_endpoint_ip_addresses,
  ))
  description = "IP Addresses for the Scheduled Start Logic App"
}

output "scheduled_start_start_function_id" {
  value       = azurerm_logic_app_action_custom.scheduled_start_start_function.id
  description = "The ID of the Logic App Custom Action for Scheduled Start Start Function."
}

output "scheduled_start_success_function_id" {
  value       = azurerm_logic_app_action_custom.scheduled_start_success_function.id
  description = "The ID of the Logic App Custom Action for Scheduled Start Success Function."
}

output "scheduled_start_terminate_id" {
  value       = azurerm_logic_app_action_custom.scheduled_start_terminate.id
  description = "The ID of the Logic App Custom Action for Scheduled Start Terminate."
}

output "scheduled_stop_daily_recurrence_id" {
  value       = azurerm_logic_app_trigger_recurrence.scheduled_stop_daily_recurrence.id
  description = "The ID of the Logic App Recurrence Trigger for Scheduled Stop."
}

output "scheduled_stop_daily_recurrence_name" {
  value       = azurerm_logic_app_trigger_recurrence.scheduled_stop_daily_recurrence.name
  description = "The name of the Logic App Recurrence Trigger for Scheduled Stop."
}

output "scheduled_stop_failed_function_id" {
  value       = azurerm_logic_app_action_custom.scheduled_stop_failed_function.id
  description = "The ID of the Logic App Custom Action for Scheduled Stop Failed Function."
}

output "scheduled_stop_logic_app_ips" {
  value = toset(concat(
    azurerm_logic_app_workflow.logic_app_scheduled_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.workflow_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_scheduled_stop.workflow_endpoint_ip_addresses
  ))
  description = "IP Addresses for the Scheduled Stop Logic App"
}

output "scheduled_stop_stop_function_id" {
  value       = azurerm_logic_app_action_custom.scheduled_stop_stop_function.id
  description = "The ID of the Logic App Custom Action for Scheduled Stop Stop Function."
}

output "scheduled_stop_succeeded_function_id" {
  value       = azurerm_logic_app_action_custom.scheduled_stop_succeeded_function.id
  description = "The ID of the Logic App Custom Action for Scheduled Stop Succeeded Function."
}

output "sequenced_start_daily_trigger_id" {
  value       = azurerm_logic_app_trigger_recurrence.sequenced_start_daily_trigger.id
  description = "The ID of the Logic App Recurrence Trigger for Sequenced Start."
}

output "sequenced_start_daily_trigger_name" {
  value       = azurerm_logic_app_trigger_recurrence.sequenced_start_daily_trigger.name
  description = "The name of the Logic App Recurrence Trigger for Sequenced Start."
}

output "sequenced_start_failed_action_id" {
  value       = azurerm_logic_app_action_custom.sequenced_start_failed_action.id
  description = "The ID of the Logic App Custom Action for Sequenced Start Failed Action."
}

output "sequenced_start_logic_app_ips" {
  value = toset(concat(
    azurerm_logic_app_workflow.logic_app_sequenced_start.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_start.workflow_outbound_ip_addresses
  ))
  description = "IP Addresses for the Sequenced Start Logic App"
}

output "sequenced_start_start_function_id" {
  value       = azurerm_logic_app_action_custom.sequenced_start_start_function.id
  description = "The ID of the Logic App Custom Action for Sequenced Start Start Function."
}

output "sequenced_start_success_action_id" {
  value       = azurerm_logic_app_action_custom.sequenced_start_success_action.id
  description = "The ID of the Logic App Custom Action for Sequenced Start Success Action."
}

output "sequenced_stop_daily_trigger_id" {
  value       = azurerm_logic_app_trigger_recurrence.sequenced_stop_daily_trigger.id
  description = "The ID of the Logic App Recurrence Trigger for Sequenced Stop."
}

output "sequenced_stop_daily_trigger_name" {
  value       = azurerm_logic_app_trigger_recurrence.sequenced_stop_daily_trigger.name
  description = "The name of the Logic App Recurrence Trigger for Sequenced Stop."
}

output "sequenced_stop_logic_app_ips" {
  value = toset(concat(
    azurerm_logic_app_workflow.logic_app_sequenced_stop.connector_outbound_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.connector_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.workflow_endpoint_ip_addresses,
    azurerm_logic_app_workflow.logic_app_sequenced_stop.workflow_endpoint_ip_addresses
  ))
  description = "IP Addresses for the Sequenced Stop Logic App"
}

output "sequenced_stop_stop_action_id" {
  value       = azurerm_logic_app_action_custom.sequenced_stop_stop_action.id
  description = "The ID of the Logic App Custom Action for Sequenced Stop Action."
}

output "sequenced_stop_success_action_id" {
  value       = azurerm_logic_app_action_custom.sequenced_stop_success_action.id
  description = "The ID of the Logic App Custom Action for Sequenced Stop Success Action."
}

output "sequenced_stop_termination_function_id" {
  value       = azurerm_logic_app_action_custom.sequenced_stop_termination_function.id
  description = "The ID of the Logic App Custom Action for Sequenced Stop Termination Function."
}

output "service_plan_id" {
  value       = azurerm_service_plan.fnc_asp.id
  description = "The ID of the Service Plan."
}

output "service_plan_name" {
  value       = azurerm_service_plan.fnc_asp.name
  description = "The name of the Service Plan."
}

output "storage_account_id" {
  value       = azurerm_storage_account.storage.id
  description = "The ID of the Storage Account."
}

output "storage_account_name" {
  value       = azurerm_storage_account.storage.name
  description = "The name of the Storage Account."
}

output "subscription_requests_store_table_name" {
  value       = azurerm_storage_table.subscription_requests_store_stable.name
  description = "The name of the Subscription Requests Store Table."
}

output "web_jobs_hosts_container_name" {
  value       = azurerm_storage_container.web_jobs_hosts.name
  description = "The name of the Web Jobs Hosts Storage Container."
}

output "web_jobs_secrets_container_name" {
  value       = azurerm_storage_container.web_jobs_secrets.name
  description = "The name of the Web Jobs Secrets Storage Container."
}
