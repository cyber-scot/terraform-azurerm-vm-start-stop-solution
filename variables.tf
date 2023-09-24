variable "allow_resource_only_permissions" {
  type        = bool
  description = "Whether users require permissions to resources to view logs"
  default     = true
}

variable "app_insights_name" {
  type        = string
  description = "The name of the App insights"
  default     = null
}

variable "app_service_plan_name" {
  type        = string
  description = "The name of the app service plan"
  default     = null
}

variable "attempt_fetch_remote_start_stop_code" {
  type        = bool
  description = "Whether the start/stop code should be remote fetched"
  default     = false
}

variable "auto_stop_logic_app_enabled" {
  type        = bool
  description = "Whether auto_stop logic app is enabled"
  default     = false
}

variable "auto_stop_logic_app_evaluation_frequency" {
  type        = string
  description = "What frequency the auto stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = "Hour"

  validation {
    condition     = var.auto_stop_logic_app_evaluation_frequency == null || can(regex("^(Month|Week|Day|Hour|Minute|Second)$", var.auto_stop_logic_app_evaluation_frequency))
    error_message = "auto_stop_logic_app_evaluation_frequency must be one of Month, Week, Day, Hour, Minute, or Second."
  }
}

variable "auto_stop_logic_app_evaluation_interval_number" {
  type        = string
  description = "What number the auto stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = 8

  validation {
    condition     = var.auto_stop_logic_app_evaluation_interval_number == null || (try(tonumber(var.auto_stop_logic_app_evaluation_interval_number) > 0, false))
    error_message = "auto_stop_logic_app_evaluation_interval_number must be a positive integer."
  }
}

variable "auto_stop_logic_app_evaluation_interval_start_time" {
  type        = string
  description = "What frequency the auto_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.auto_stop_logic_app_evaluation_interval_start_time == null || can(timestamp(var.auto_stop_logic_app_evaluation_interval_start_time))
    error_message = "The start_time must be in a valid RFC3339 format, or left as null."
  }
}

variable "auto_stop_logic_app_name" {
  type        = string
  description = "The name of the auto_stop logic app"
  default     = null
}

variable "auto_stop_query_action_groups" {
  type        = set(string)
  description = "The action groups for the auto_stop_query"
  default     = []
}

variable "auto_stop_query_alert_name" {
  type        = string
  description = "The name of the alert name"
  default     = null
}

variable "auto_stop_query_alert_scopes" {
  type        = set(string)
  description = "The name of the alert name"
  default     = []
}

variable "auto_stop_resource_group_scopes" {
  type        = set(string)
  description = "The scopes for the auto_stop logic app resource groups"
  default = [
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1/",
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg2/"
  ]
}

variable "auto_stop_schedules" {
  description = "A list of schedules for auto_stop logic app"
  type = list(object({
    days    = optional(list(string), [])
    hours   = optional(list(number), [])
    minutes = optional(list(number), [])
  }))
  default = []
}

variable "cmk_for_query_forced" {
  type        = bool
  description = "Whether or not a Customer Managed Key for the query is forced"
  default     = false
}

variable "create_law_linked_app_insights" {
  type        = bool
  description = "Whether a law workspace linked app insights should be used - if set false, the old type which will be used which will be deprecated in Feb 2024"
  default     = false
}

variable "create_new_law" {
  type        = bool
  description = "Whether or not you wish to create a new workspace, if set to true, a new one will be created, if set to false, a data read will be performed on a data source"
  default     = false
}

variable "daily_quota_gb" {
  type        = string
  description = "The amount of gb set for max daily ingetion"
  default     = "30"
}

variable "dashboard_name" {
  type        = string
  description = "The name of the dashboard that is made for the start stop solution"
  default     = null
}

variable "email_receivers" {
  type = list(object({
    email_address = string
    name          = string
  }))
  default     = []
  description = "List of email receivers for the action group"
}

variable "function_app_name" {
  type        = string
  description = "The name of function app"
  default     = null
}

variable "internet_ingestion_enabled" {
  type        = bool
  description = "Whether internet ingestion is enabled"
  default     = null
}

variable "internet_query_enabled" {
  type        = bool
  description = "Whether or not your workspace can be queried from the internet"
  default     = null
}

variable "law_id" {
  type        = string
  description = "The ID of the log analytics workspace id to link app insights too"
  default     = null
}

variable "law_name" {
  type        = string
  description = "The name of a log analytics workspace"
  default     = null
}

variable "law_sku" {
  type        = string
  description = "The sku of the log analytics workspace"
  default     = "PerGB2018"
}

variable "local_authentication_disabled" {
  type        = bool
  description = "Whether local authentication is enabled, defaults to false"
  default     = false
}

variable "location" {
  type        = string
  description = "The location (region) the resource should be put in, e.g. uksouth"
}

variable "lock_level" {
  type        = string
  description = "The name of the lock_level, can only be CanNotDelete or Readonly"
  default     = null
  validation {
    condition     = var.lock_level != "CanNotDelete" || var.lock_level != "ReadOnly"
    error_message = "The only accepted parameters for lock_level is are CanNotDelete or ReadOnly."
  }
}

variable "logic_app_default_timezone" {
  type        = string
  description = "The timezone in which all logic app schedules are set to"
  default     = null
}

variable "microsoft_instrumentation_key" {
  type        = string
  description = "The centralised microsoft instrumentation key for start/stop telemetry"
  default     = null
}

variable "name" {
  type        = string
  description = "The name of the resource"
}

variable "notification_action_group_name" {
  type        = string
  default     = null
  description = "The name of the Start/Start alert action group"
}

variable "notification_action_group_short_name" {
  type        = string
  description = "The short name for the notification, normally used in SMS"
  default     = null
}

variable "reservation_capacity_in_gb_per_day" {
  type        = string
  description = "The reservation capacity gb per day, can only be used with CapacityReservation SKU"
  default     = "30"
}

variable "retention_in_days" {
  type        = string
  description = "The number of days for retention, between 7 and 730"
  default     = "30"
}

variable "scheduled_query_action_groups" {
  type        = set(string)
  description = "The action groups for the scheduled_query"
  default     = []

}

variable "scheduled_query_alert_scopes" {
  type        = set(string)
  description = "The action groups for the scheduled_scopes"
  default     = []
}

variable "scheduled_start_logic_app_enabled" {
  type        = bool
  description = "Whether scheduled_start logic app is enabled"
  default     = false
}

variable "scheduled_start_logic_app_evaluation_frequency" {
  type        = string
  description = "What frequency the scheduled_start logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.scheduled_start_logic_app_evaluation_frequency == null || can(regex("^(Month|Week|Day|Hour|Minute|Second)$", var.scheduled_start_logic_app_evaluation_frequency))
    error_message = "scheduled_start_logic_app_evaluation_frequency must be one of Month, Week, Day, Hour, Minute, or Second."
  }
}

variable "scheduled_start_logic_app_evaluation_interval_number" {
  type        = number
  description = "What frequency the scheduled_start logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.scheduled_start_logic_app_evaluation_interval_number == null || (try(tonumber(var.scheduled_start_logic_app_evaluation_interval_number) > 0, false))
    error_message = "scheduled_start_logic_app_evaluation_interval_number must be a positive integer."
  }
}

variable "scheduled_start_logic_app_evaluation_interval_start_time" {
  type        = string
  description = "What frequency the scheduled_start logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.scheduled_start_logic_app_evaluation_interval_start_time == null || can(timestamp(var.scheduled_start_logic_app_evaluation_interval_start_time))
    error_message = "The start_time must be in a valid RFC3339 format, or left as null."
  }
}

variable "scheduled_start_logic_app_name" {
  type        = string
  description = "The name of the scheduled start name"
  default     = null
}

variable "scheduled_start_resource_group_scopes" {
  type        = set(string)
  description = "The scopes for the scheduled start logic app resource groups"
  default = [
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1/",
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg2/"
  ]
}

variable "scheduled_start_schedules" {
  description = "A list of schedules for scheduled_start logic app"
  type = list(object({
    days    = optional(list(string), [])
    hours   = optional(list(number), [])
    minutes = optional(list(number), [])
  }))
  default = []
}

variable "scheduled_start_stop_query_alert_name" {
  type        = string
  description = "The name of the scheduled start stop function"
  default     = null
}

variable "scheduled_stop_logic_app_enabled" {
  type        = bool
  description = "Whether sequenced_stop logic app is enabled"
  default     = false
}

variable "scheduled_stop_logic_app_evaluation_frequency" {
  type        = string
  description = "What frequency the scheduled_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = "Hour"

  validation {
    condition     = var.scheduled_stop_logic_app_evaluation_frequency == null || can(regex("^(Month|Week|Day|Hour|Minute|Second)$", var.scheduled_stop_logic_app_evaluation_frequency))
    error_message = "scheduled_stop_logic_app_evaluation_frequency must be one of Month, Week, Day, Hour, Minute, or Second."
  }
}

variable "scheduled_stop_logic_app_evaluation_interval_number" {
  type        = number
  description = "What frequency the scheduled_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = 8

  validation {
    condition     = var.scheduled_stop_logic_app_evaluation_interval_number == null || (try(tonumber(var.scheduled_stop_logic_app_evaluation_interval_number) > 0, false))
    error_message = "scheduled_stop_logic_app_evaluation_interval_number must be a positive integer."
  }
}

variable "scheduled_stop_logic_app_evaluation_interval_start_time" {
  type        = string
  description = "What frequency the scheduled_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.scheduled_stop_logic_app_evaluation_interval_start_time == null || can(timestamp(var.scheduled_stop_logic_app_evaluation_interval_start_time))
    error_message = "The start_time must be in a valid RFC3339 format, or left as null."
  }
}

variable "scheduled_stop_logic_app_name" {
  type        = string
  description = "The name of the scheduled_stop logic app"
  default     = null
}

variable "scheduled_stop_resource_group_scopes" {
  type        = set(string)
  description = "The scopes for the scheduled stop logic app resource groups"
  default = [
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1/",
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg2/"
  ]
}

variable "scheduled_stop_schedules" {
  description = "A list of schedules for scheduled_stop logic app"
  type = list(object({
    days    = optional(list(string), [])
    hours   = optional(list(number), [])
    minutes = optional(list(number), [])
  }))
  default = []
}

variable "sequenced_query_action_groups" {
  type        = set(string)
  description = "The action groups for the sequenced_query"
  default     = []
}

variable "sequenced_query_alert_scopes" {
  type        = set(string)
  description = "The action groups for the sequenced_scopes"
  default     = []
}

variable "sequenced_start_logic_app_enabled" {
  type        = bool
  description = "Whether sequenced_start logic app is enabled"
  default     = false
}

variable "sequenced_start_logic_app_evaluation_frequency" {
  type        = string
  description = "What frequency the sequenced_start logic app should be evaluating at, for example, Hour, Day etc"
  default     = "Hour"

  validation {
    condition     = var.sequenced_start_logic_app_evaluation_frequency == null || can(regex("^(Month|Week|Day|Hour|Minute|Second)$", var.sequenced_start_logic_app_evaluation_frequency))
    error_message = "sequenced_start_logic_app_evaluation_frequency must be one of Month, Week, Day, Hour, Minute, or Second."
  }
}

variable "sequenced_start_logic_app_evaluation_interval_number" {
  type        = number
  description = "What frequency the sequenced_start logic app should be evaluating at, for example, Hour, Day etc"
  default     = 8

  validation {
    condition     = var.sequenced_start_logic_app_evaluation_interval_number == null || (try(tonumber(var.sequenced_start_logic_app_evaluation_interval_number) > 0, false))
    error_message = "sequenced_start_logic_app_evaluation_interval_number must be a positive integer."
  }
}

variable "sequenced_start_logic_app_evaluation_interval_start_time" {
  type        = string
  description = "What frequency the sequenced_start logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.sequenced_start_logic_app_evaluation_interval_start_time == null || can(timestamp(var.sequenced_start_logic_app_evaluation_interval_start_time))
    error_message = "The start_time must be in a valid RFC3339 format, or left as null."
  }
}

variable "sequenced_start_logic_app_name" {
  type        = string
  description = "The name of the sequenced start logic app name"
  default     = null
}

variable "sequenced_start_resource_group_scopes" {
  type        = set(string)
  description = "The scopes for the sequenced start logic app resource groups"
  default = [
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1/",
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg2/"
  ]
}

variable "sequenced_start_schedules" {
  description = "A list of schedules for sequenced_start logic app"
  type = list(object({
    days    = optional(list(string), [])
    hours   = optional(list(number), [])
    minutes = optional(list(number), [])
  }))
  default = []
}

variable "sequenced_stop_logic_app_enabled" {
  type        = bool
  description = "Whether sequenced_stop logic app is enabled"
  default     = false
}

variable "sequenced_stop_logic_app_evaluation_frequency" {
  type        = string
  description = "What frequency the sequenced_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = "Hour"

  validation {
    condition     = var.sequenced_stop_logic_app_evaluation_frequency == null || can(regex("^(Month|Week|Day|Hour|Minute|Second)$", var.sequenced_stop_logic_app_evaluation_frequency))
    error_message = "sequenced_stop_logic_app_evaluation_frequency must be one of Month, Week, Day, Hour, Minute, or Second."
  }
}

variable "sequenced_stop_logic_app_evaluation_interval_number" {
  type        = number
  description = "What frequency the sequenced_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = 8

  validation {
    condition     = var.sequenced_stop_logic_app_evaluation_interval_number == null || (try(tonumber(var.sequenced_stop_logic_app_evaluation_interval_number) > 0, false))
    error_message = "sequenced_stop_logic_app_evaluation_interval_number must be a positive integer."
  }
}

variable "sequenced_stop_logic_app_evaluation_interval_start_time" {
  type        = string
  description = "What frequency the sequenced_stop logic app should be evaluating at, for example, Hour, Day etc"
  default     = null

  validation {
    condition     = var.sequenced_stop_logic_app_evaluation_interval_start_time == null || can(timestamp(var.sequenced_stop_logic_app_evaluation_interval_start_time))
    error_message = "The start_time must be in a valid RFC3339 format, or left as null."
  }
}

variable "sequenced_stop_logic_app_name" {
  type        = string
  description = "The name of the sequenced stop logic app"
  default     = null
}

variable "sequenced_stop_resource_group_scopes" {
  type        = set(string)
  description = "The scopes for the sequenced stop logic app resource groups"
  default = [
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1/",
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg2/"
  ]
}

variable "sequenced_stop_schedules" {
  description = "A list of schedules for sequenced_stop logic app"
  type = list(object({
    days    = optional(list(string), [])
    hours   = optional(list(number), [])
    minutes = optional(list(number), [])
  }))
  default = []
}

variable "smart_detection_action_group_name" {
  type        = string
  description = "The smart detection ag name"
  default     = null
}

variable "smart_detection_action_group_short_name" {
  type        = string
  description = "The short name for the smart detection action group"
  default     = null
}

variable "start_stop_source_url" {
  type        = string
  description = "The URL of the source file for start/stop"
  default     = "https://startstopv2prod.blob.core.windows.net/artifacts/StartStopV2.zip"
}

variable "storage_account_firewall_bypass" {
  description = "The bypass features of the storage account firewall"
  type        = set(string)
  default     = ["AzureServices", "Logging", "Metrics"]
}

variable "storage_account_firewall_default_action" {
  description = "The default action of the storage account firewall"
  type        = string
  default     = "Allow"
}

variable "storage_account_firewall_subnet_ids" {
  description = "List of subnet_ids"
  type        = list(string)
  default     = []
}

variable "storage_account_firewall_user_ip_rules" {
  description = "List of user-specified IP rules"
  type        = list(string)
  default     = []
}

variable "storage_account_fiwall_subnet_ids" {
  description = "List of user-specified subnet IDs"
  type        = list(string)
  default     = []
}

variable "storage_account_name" {
  type        = string
  description = "The name of the storage account to be made"
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "The tags assigned to the resource"
}
