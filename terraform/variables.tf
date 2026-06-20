variable "tenant_id" {
  type = string
}

variable "subscription_id" {
  type = string
}

variable "rg_name" {
  type    = string
  default = "PolicyAwareRAG"
}

variable "location" {
  type    = string
  default = "uksouth"
}

variable "project_prefix" {
  type    = string
  default = "policyrag"
}

variable "blob_container_name" {
  type    = string
  default = "landing"
}

variable "cosmos_database_name" {
  type    = string
  default = "policy_rag_db"
}
variable "common_tags" {
  type = map(string)
  default = {
    environment = "dev"
    owner       = "policy-rag"
  }
}

variable "foundry_project_name" {
  type    = string
  default = "PolicyAwareRag"
}

variable "gpt_model_deployment_name" {
  type    = string
  default = "gpt-4o-mini"
}

variable "gpt_model_name" {
  type    = string
  default = "gpt-4o-mini"
}

variable "gpt_model_version" {
  type    = string
  default = null
  nullable = true
}

variable "gpt_model_sku_name" {
  type    = string
  default = "GlobalStandard"
}

variable "gpt_model_capacity" {
  type    = number
  default = 10
}