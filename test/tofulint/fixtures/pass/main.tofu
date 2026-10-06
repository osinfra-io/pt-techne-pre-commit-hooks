terraform {
  required_version = ">= 1.13.0"
}

variable "message" {
  type    = string
  default = "lint passes"
}

output "message" {
  value = var.message
}
