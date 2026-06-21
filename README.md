# Policy-Aware RAG Gateway

This workspace contains baseline Terraform and Python code for a policy-aware Retrieval-Augmented Generation gateway.

- Terraform: `terraform/` contains `main.tf`, `variables.tf`, and `outputs.tf` for provisioning Azure resources (Function App, Key Vault, Cosmos DB, Blob Storage, Cognitive Account).
- Python: Orchestrator and modules for policy validation, retrieval, decision graph, and compliance scanning.

Next steps:
- Implement and wire Azure Function activity bindings for the activities in `activities.py`.
- Populate real ODRL policies and deploy Terraform with appropriate `tenant_id` and `subscription_id`.
- Harden networking, private endpoints, and conditional access for production.

## Infrastructure Configuration and Deployment

Use `terraform/deploy-terraform.ps1` to initialize and deploy infrastructure.

### 1. Configure Deployment Parameters

Before running the script, update these parameters in `terraform/deploy-terraform.ps1`:

- `SubscriptionId` (required): Your Azure subscription ID.
- `ResourceGroup` (required): Resource group name for deployment.
- `Environment` (required): Environment suffix used in resource naming (`dev`, `test`, `prod`, etc.).
- `Region` (optional): Azure region display name (default is `West Europe`).

Optional AI Foundry and model deployment parameters:

- `FoundryProjectName`: AI Foundry project name (default: `PolicyAwareRag`).
- `GptModelDeploymentName`: Deployment name for the chat model (default: `gpt-5-5`).
- `GptModelName`: Chat model name to deploy (default: `gpt-5.5`).
- `GptModelVersion`: Chat model version. Leave blank to use provider/service defaults.
- `GptModelSkuName`: Chat model SKU (default: `GlobalStandard`).
- `GptModelCapacity`: Chat model capacity units (default: `10`).

The script derives Terraform values and naming prefixes from these parameters.

### 2. Prerequisites

The following are required before deployment:

- Azure CLI installed and available on `PATH`.
- Terraform CLI installed and available on `PATH`.
- Azure login completed with permissions to create/update resources in the target subscription/resource group.
- Access to required Azure resource providers in your subscription.

### 3. Deploy Infrastructure

Run from the repository root:

```powershell
.\terraform\deploy-terraform.ps1
```

Or override parameters at runtime:

```powershell
.\terraform\deploy-terraform.ps1 -SubscriptionId "<subscription-id>" -ResourceGroup "<rg-name>" -Environment "dev" -Region "West Europe"
```

Example with explicit Foundry and model overrides:

```powershell
.\terraform\deploy-terraform.ps1 `
	-SubscriptionId "<subscription-id>" `
	-ResourceGroup "<rg-name>" `
	-Environment "dev" `
	-Region "West Europe" `
	-FoundryProjectName "PolicyAwareRag" `
	-GptModelDeploymentName "gpt-5-5" `
	-GptModelName "gpt-5.5" `
	-GptModelSkuName "GlobalStandard" `
```

> Model and SKU availability are region and subscription dependent. If deployment fails with model support errors, update model name/SKU/version or use a different region.

### 4. Validate Deployment

After deployment completes, review outputs:

```powershell
terraform -chdir=terraform output
```

Key outputs to note:

- `function_app_name`: Azure Function App name.
- `cosmos_db_endpoint`: Cosmos DB account endpoint.
- `key_vault_id`: Key Vault resource id.
- `ai_foundry_endpoint`: Azure AI Foundry endpoint.
- `gpt_model_deployment_name`: Chat model deployment name.

### 5. Load Sample Data

Open `utils/Load_VectorDB.ipynb` in VS Code or Jupyter and run the cells from top to bottom.

The notebook performs the following steps:

1. Installs the notebook dependencies with `%pip install azure-cosmos requests tqdm sentence-transformers torch`.
2. Downloads the Enron sample archive from CMU if it is not already cached locally.
3. Parses and cleans the email data.
4. Generates embeddings locally with `sentence-transformers`.
5. Connects to Azure Cosmos DB and loads the records into the `EnronEmailVectorStore` container.

Before running the notebook, set these environment variables in your notebook session or local settings:

- `COSMOS_ENDPOINT`
- `COSMOS_KEY`
- `COSMOS_DATABASE`
- `COSMOS_ENRON_COLLECTION`

For this sample, the notebook expects `COSMOS_ENRON_COLLECTION` to match the Cosmos container name created by Terraform.

After the notebook finishes, verify that the container contains the loaded sample records in Azure Cosmos DB.

### 6. Run the Azure Function App

This repository now includes the Azure Functions project root and a starter HTTP trigger that wires the existing orchestration and activities into a deployable Function App.

The runtime is intended for Python on Linux with Durable Functions support, so the local environment should match the packages in `requirements.txt` and the app settings in `local.settings.json`.

For local execution:

1. Install Python 3.11 and Azure Functions Core Tools.
2. Create and activate a virtual environment.
3. Install the dependencies from `requirements.txt`.
4. Set the local app settings to match your deployed resources, especially `AzureWebJobsStorage`, `FUNCTIONS_WORKER_RUNTIME`, `COSMOS_DB_ENDPOINT`, `COSMOS_DB_DATABASE`, `BLOB_CONTAINER`, `KEYVAULT_NAME`, and `AI_FOUNDRY_ENDPOINT`.
5. Start the host from the project root with Azure Functions Core Tools.
6. Call `POST /api/orchestrators/start` with a JSON body to start a durable orchestration instance.

For Azure execution:

1. Use `terraform -chdir=terraform output` to get the deployed Function App name and supporting resource values.
2. Confirm the Function App application settings match the deployed resources and secrets in Key Vault.
3. Deploy the Python function code to the Azure Function App.
4. Invoke `POST /api/orchestrators/start` with a payload that includes `principal`, `odrl_policy`, `query_embedding`, `action`, `cosmos_endpoint`, and `database`.
5. Use one of the policies in `odrl_policies/` to test a restrictive role, a limited role, or a full-access role.
6. Review Application Insights and Function App logs if the orchestration fails, returns a denied response, or redacts output.

The orchestration function is registered in `function_app.py`, and the activity wrappers keep the current implementations in `orchestrator.py` and `activities.py` intact.