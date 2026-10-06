variable "region" {
  description = "AWS region to deploy into (GuardDuty must be enabled here)"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "ir-ec2-isolation"
}

variable "min_severity" {
  description = "Lowest GuardDuty severity that triggers isolation (7 = HIGH)"
  type        = number
  default     = 7
}

variable "dry_run" {
  description = "Start in dry-run mode: log the plan, change nothing. Flip to false after review."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Optional email subscribed to the SOC alert topic"
  type        = string
  default     = ""
}
