provider "azurerm" {
  features {}
  tenant_id = var.tenant_id
  subscription_id = var.subscription_id
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
  tags = var.common_tags
}

resource "azurerm_user_assigned_identity" "svc_identity" {
  name                = "${var.project_prefix}-svc-identity"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  tags                = var.common_tags
}

resource "azurerm_storage_account" "func_sa" {
  name                     = lower("${var.project_prefix}funcsa")
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = false
  tags                     = var.common_tags
}

resource "azurerm_storage_container" "landing" {
  name                  = var.blob_container_name
  storage_account_id    = azurerm_storage_account.func_sa.id
  container_access_type = "private"
}

resource "azurerm_service_plan" "func_plan" {
  name                = "${var.project_prefix}-func-plan"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "Y1"
  tags = var.common_tags
}

resource "azurerm_linux_function_app" "gateway_function" {
  name                       = "${var.project_prefix}-gateway-func"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  service_plan_id            = azurerm_service_plan.func_plan.id
  storage_account_name       = azurerm_storage_account.func_sa.name
  storage_account_access_key = azurerm_storage_account.func_sa.primary_access_key
  identity {
    type = "SystemAssigned"
  }
  site_config {
    application_stack {
      python_version = "3.11"
    }
  }
  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "python"
    WEBSITE_RUN_FROM_PACKAGE = "1"
    BLOB_CONTAINER           = azurerm_storage_container.landing.name
    KEYVAULT_NAME            = azurerm_key_vault.kv.name
    COSMOS_DB_ACCOUNT        = azurerm_cosmosdb_account.cosmos.endpoint
    AZURE_CLIENT_ID          = azurerm_user_assigned_identity.svc_identity.client_id
  }
  tags = var.common_tags
}

resource "azurerm_key_vault" "kv" {
  name                        = "${var.project_prefix}-kv"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  tenant_id                   = var.tenant_id
  sku_name                    = "standard"
  purge_protection_enabled    = false
  enabled_for_disk_encryption = false
  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
  tags = var.common_tags
}

resource "azurerm_key_vault_access_policy" "terraform" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id     = data.azurerm_client_config.current.tenant_id
  object_id     = data.azurerm_client_config.current.object_id

  secret_permissions = [
    "Get",
    "List",
    "Set",
    "Delete",
    "Recover",
    "Purge",
  ]
}

resource "azurerm_key_vault_access_policy" "function_app" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id     = var.tenant_id
  object_id     = azurerm_linux_function_app.gateway_function.identity[0].principal_id

  secret_permissions = [
    "Get",
    "List",
  ]
}

resource "azurerm_cosmosdb_account" "cosmos" {
  name                = "${var.project_prefix}-cosmos"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  consistency_policy {
    consistency_level = "Session"
  }
  geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
  }
  automatic_failover_enabled = false
  is_virtual_network_filter_enabled = false
  tags = var.common_tags
}

resource "azurerm_cosmosdb_sql_database" "db" {
  name                = var.cosmos_database_name
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
  throughput          = 4000
}

resource "azurerm_cosmosdb_sql_container" "vector_db" {
  name                = "VectorDatabase"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/partitionKey"]
  throughput          = 4000
  indexing_policy {
    indexing_mode = "consistent"
  }
}

resource "azurerm_cosmosdb_sql_container" "audit_db" {
  name                = "AuditStorage"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/transactionId"]
  throughput          = 4000
  indexing_policy {
    indexing_mode = "consistent"
  }
}

resource "azurerm_role_assignment" "svc_blob_contributor" {
  scope                = azurerm_storage_account.func_sa.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.svc_identity.principal_id
}

resource "azurerm_cognitive_account" "ai_foundry" {
  name                = "${var.project_prefix}-ai"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  kind                = "AIServices"
  sku_name            = "S0"
  custom_subdomain_name = "${var.project_prefix}-ai"
  project_management_enabled = true

  identity {
    type = "SystemAssigned"
  }

  tags = var.common_tags
}

resource "azurerm_cognitive_account_project" "policy_aware_rag" {
  name                 = var.foundry_project_name
  cognitive_account_id = azurerm_cognitive_account.ai_foundry.id
  location             = azurerm_resource_group.rg.location
  tags                 = var.common_tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cognitive_deployment" "gpt55" {
  name                 = var.gpt_model_deployment_name
  cognitive_account_id = azurerm_cognitive_account.ai_foundry.id

  model {
    format  = "OpenAI"
    name    = var.gpt_model_name
    version = var.gpt_model_version
  }

  sku {
    name     = var.gpt_model_sku_name
    capacity = var.gpt_model_capacity
  }
}

resource "azurerm_cognitive_deployment" "text_embedding" {
  name                 = var.embedding_model_deployment_name
  cognitive_account_id = azurerm_cognitive_account.ai_foundry.id

  model {
    format  = "OpenAI"
    name    = var.embedding_model_name
    version = var.embedding_model_version
  }

  sku {
    name     = var.embedding_model_sku_name
    capacity = var.embedding_model_capacity
  }
}

resource "azurerm_role_assignment" "func_ai_contributor" {
  scope                = azurerm_cognitive_account.ai_foundry.id
  role_definition_name = "Cognitive Services User"
  principal_id         = azurerm_linux_function_app.gateway_function.identity[0].principal_id
}

resource "azurerm_key_vault_secret" "ai_endpoint" {
  name         = "ai-foundry-endpoint"
  value        = azurerm_cognitive_account.ai_foundry.endpoint
  key_vault_id = azurerm_key_vault.kv.id

  depends_on = [azurerm_key_vault_access_policy.terraform]
}

resource "azurerm_key_vault_secret" "ai_foundry_project_id" {
  name         = "ai-foundry-project-id"
  value        = azurerm_cognitive_account_project.policy_aware_rag.id
  key_vault_id = azurerm_key_vault.kv.id

  depends_on = [azurerm_key_vault_access_policy.terraform]
}

resource "azurerm_key_vault_secret" "ai_chat_deployment_name" {
  name         = "ai-chat-deployment-name"
  value        = azurerm_cognitive_deployment.gpt55.name
  key_vault_id = azurerm_key_vault.kv.id

  depends_on = [azurerm_key_vault_access_policy.terraform]
}

resource "azurerm_key_vault_secret" "ai_embedding_deployment_name" {
  name         = "ai-embedding-deployment-name"
  value        = azurerm_cognitive_deployment.text_embedding.name
  key_vault_id = azurerm_key_vault.kv.id

  depends_on = [azurerm_key_vault_access_policy.terraform]
}

resource "azurerm_cosmosdb_sql_role_definition" "svc_cosmos_data_contrib" {
  name                = "${var.project_prefix}-cosmos-sql-data-contributor"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
  role_definition_id  = "b7af0f9d-4d1d-4dc0-a7f5-8b0f3c7f9a11"

  permissions {
    data_actions = ["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/*"]
  }

  assignable_scopes = [azurerm_cosmosdb_account.cosmos.id]
}

resource "azurerm_cosmosdb_sql_role_assignment" "svc_cosmos_contrib" {
  name                = "c8e6c2d1-5b41-4c8f-8d2d-9d9d5e0e5b7f"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
  role_definition_id  = azurerm_cosmosdb_sql_role_definition.svc_cosmos_data_contrib.id
  principal_id        = azurerm_user_assigned_identity.svc_identity.principal_id
  scope               = azurerm_cosmosdb_account.cosmos.id
}

output "function_app_name" {
  value = azurerm_linux_function_app.gateway_function.name
}

output "key_vault_id" {
  value = azurerm_key_vault.kv.id
}

output "cosmos_db_endpoint" {
  value = azurerm_cosmosdb_account.cosmos.endpoint
}

output "ai_foundry_endpoint" {
  value = azurerm_cognitive_account.ai_foundry.endpoint
}

output "ai_foundry_project_id" {
  value = azurerm_cognitive_account_project.policy_aware_rag.id
}

output "gpt_model_deployment_name" {
  value = azurerm_cognitive_deployment.gpt55.name
}

output "embedding_model_deployment_name" {
  value = azurerm_cognitive_deployment.text_embedding.name
}
