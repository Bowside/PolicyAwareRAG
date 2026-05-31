# Deployment parameters
# IMPORTANT: Change these values before deployment to match your Azure environment.
# Terraform owns all infrastructure creation.
# This script only maps inputs, derives naming values, and runs the Terraform workflow.
# - SubscriptionId: REQUIRED. Use your own Azure subscription ID.
# - ResourceGroup: REQUIRED. Name of the resource group Terraform will create/manage.
# - Environment: REQUIRED. Short environment suffix used in naming (for example: dev, test, prod).
# - Region: Change if you do not want West Europe.
# - Foundry/Model parameters: Optional overrides for project and model deployments.
param(
    [string]$SubscriptionId = "85cec0e7-ca91-4f06-a77c-f951f264ba2d",
    [string]$Region = "West Europe",
    [string]$ResourceGroup = "PolicyAwareRAG",
    [string]$Environment = "dev",
    [string]$FoundryProjectName = "PolicyAwareRag",
    [string]$GptModelDeploymentName = "gpt-4o-mini",
    [string]$GptModelName = "gpt-4o-mini",
    [string]$GptModelVersion = "",
    [int]$GptModelCapacity = 10,
    [string]$GptModelSkuName = "GlobalStandard",
    [string]$EmbeddingModelDeploymentName = "text-embedding",
    [string]$EmbeddingModelName = "text-embedding-3-large",
    [string]$EmbeddingModelVersion = "",
    [int]$EmbeddingModelCapacity = 10,
    [string]$EmbeddingModelSkuName = "GlobalStandard"
)

function Ensure-Command {
    param([string]$cmd)
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if (-not $found) {
        Write-Error "Required command '$cmd' not found in PATH. Please install it and retry."
        exit 1
    }
}

Ensure-Command -cmd az
Ensure-Command -cmd terraform

if ($SubscriptionId -eq "<your-azure-subscription-id>" -or $ResourceGroup -eq "<your-resource-group-name>") {
    Write-Error "Update SubscriptionId and ResourceGroup parameter values before running this script."
    exit 1
}

# map common region names -> terraform location and 3-letter code used in naming
$regionMap = @{
    "West Europe" = @{ location = "westeurope"; code = "weu" }
}

if ($regionMap.ContainsKey($Region)) {
    $Location = $regionMap[$Region].location
    $RegionCode = $regionMap[$Region].code
} else {
    $Location = ($Region -replace ' ', '' -replace '-', '').ToLower()
    $RegionCode = $Location.Substring(0, [Math]::Min(3, $Location.Length))
}

Write-Host "Setting subscription to $SubscriptionId"
az account set --subscription $SubscriptionId

Write-Host "Discovering tenant id for subscription"
$tenantId = az account show --subscription $SubscriptionId --query tenantId -o tsv
if (-not $tenantId) {
    Write-Error "Could not determine tenant id. Ensure you're logged in with 'az login'."
    exit 1
}

# Build a basic project prefix (Terraform expects a single project_prefix variable); per-service names
# follow the convention: {2-letter service}{region3}policyawarerag{env}
$env = $Environment
$projectPrefix = "policyawarerag$env"

$exampleNames = @{
    function = "fa${RegionCode}policyawarerag${env}"
    storage  = "st${RegionCode}policyawarerag${env}"
    keyvault = "kv${RegionCode}policyawarerag${env}"
    cosmos   = "db${RegionCode}policyawarerag${env}"
    ai       = "ai${RegionCode}policyawarerag${env}"
}

Write-Host "Example resource names (follow naming convention):"
foreach ($k in $exampleNames.Keys) { Write-Host " - ${k}:`t$($exampleNames[$k])" }

$terraformDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $terraformDir

Write-Host "Initializing Terraform..."
terraform init

if ($LASTEXITCODE -ne 0) {
    Write-Error "Terraform init failed (exit code $LASTEXITCODE)"
    Pop-Location
    exit $LASTEXITCODE
}

Write-Host "Planning and applying Terraform configuration..."
$terraformVars = @(
    "-var", "tenant_id=$tenantId",
    "-var", "subscription_id=$SubscriptionId",
    "-var", "rg_name=$ResourceGroup",
    "-var", "location=$Location",
    "-var", "project_prefix=$projectPrefix",
    "-var", "foundry_project_name=$FoundryProjectName",
    "-var", "gpt_model_deployment_name=$GptModelDeploymentName",
    "-var", "gpt_model_name=$GptModelName",
    "-var", "gpt_model_capacity=$GptModelCapacity",
    "-var", "gpt_model_sku_name=$GptModelSkuName",
    "-var", "embedding_model_deployment_name=$EmbeddingModelDeploymentName",
    "-var", "embedding_model_name=$EmbeddingModelName",
    "-var", "embedding_model_capacity=$EmbeddingModelCapacity",
    "-var", "embedding_model_sku_name=$EmbeddingModelSkuName"
)

if (-not [string]::IsNullOrWhiteSpace($GptModelVersion)) {
    $terraformVars += @("-var", "gpt_model_version=$GptModelVersion")
}

if (-not [string]::IsNullOrWhiteSpace($EmbeddingModelVersion)) {
    $terraformVars += @("-var", "embedding_model_version=$EmbeddingModelVersion")
}

terraform apply -auto-approve @terraformVars

if ($LASTEXITCODE -ne 0) {
    Write-Error "Terraform apply failed (exit code $LASTEXITCODE)"
    Pop-Location
    exit $LASTEXITCODE
}

Pop-Location

Write-Host "Terraform apply completed. Review outputs with: terraform -chdir='$terraformDir' output"
