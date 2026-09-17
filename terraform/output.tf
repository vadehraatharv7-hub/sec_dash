output "vm_public_ip" {
  value       = azurerm_public_ip.pip.ip_address
  description = "Public IP address of the honeypot sensor VM"
}

output "monitoring_vm_public_ip" {
  value       = azurerm_public_ip.pip_monitoring.ip_address
  description = "Public IP address of the SecDash monitoring & operations VM"
}
