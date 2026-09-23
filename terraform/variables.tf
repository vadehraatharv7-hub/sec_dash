variable "admin_public_ip" {
  type        = string
  description = "Allowed administrative public IP address for SSH and management access"

  validation {
    condition     = can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$", var.admin_public_ip))
    error_message = "The admin_public_ip must be a valid IPv4 address without CIDR (e.g. 203.0.113.45)."
  }
}
