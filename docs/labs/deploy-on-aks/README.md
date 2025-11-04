# Deploy Azure API MCP on AKS with OIDC Workload Identity

This guide walks you through deploying the Azure API MCP server on Azure Kubernetes Service (AKS) using OIDC-based Workload Identity for secure, pod-level Azure authentication.

## Overview

Azure Workload Identity for AKS enables your pods to authenticate to Azure services using Kubernetes ServiceAccount tokens, eliminating the need for storing credentials in your cluster. The azure-api-mcp server will use this federated identity to execute Azure CLI commands securely.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         AKS Cluster                         │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              azure-api-mcp Pod                      │   │
│  │                                                     │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │  ServiceAccount Token (projected volume)      │ │   │
│  │  │  → AZURE_FEDERATED_TOKEN_FILE                 │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  │                      ↓                              │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │  azure-api-mcp process                        │ │   │
│  │  │  - Reads federated token                      │ │   │
│  │  │  - Exchanges for Azure access token           │ │   │
│  │  │  - Executes Azure CLI commands                │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────┘   │
│                      ↓                                      │
│              ServiceAccount:                                │
│              azure-api-mcp-sa                              │
│              (annotated with Azure Client ID)               │
└─────────────────────────────────────────────────────────────┘
                       ↓
         Federated Identity Credential
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                      Azure AD                               │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │         Managed Identity                              │ │
│  │         (azure-api-mcp-identity)                      │ │
│  │                                                       │ │
│  │  - Trusts AKS OIDC Issuer                            │ │
│  │  - Validates ServiceAccount token                    │ │
│  │  - Issues Azure access token                         │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                       ↓
         Azure RBAC Role Assignment
                       ↓
┌─────────────────────────────────────────────────────────────┐
│             Azure Resources (Subscription)                  │
│                                                             │
│  - Virtual Machines                                         │
│  - Storage Accounts                                         │
│  - AKS Clusters                                             │
│  - etc.                                                     │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- An AKS cluster with OIDC Issuer enabled
- `kubectl` configured to access your cluster
- Permissions to create Azure Managed Identities and role assignments
- Docker image of azure-api-mcp (build from this repo or use pre-built)

## Step 1: Prepare Azure Resources

### 1.1 Set Environment Variables

```bash
export RESOURCE_GROUP="<your-rg>"
export AKS_CLUSTER_NAME="<your-aks-cluster>"
export LOCATION="<your-location>"
export IDENTITY_NAME="azure-api-mcp-identity"
export SERVICE_ACCOUNT_NAME="azure-api-mcp-sa"
export SERVICE_ACCOUNT_NAMESPACE="default"
export SUBSCRIPTION_ID="<your-subscription-id>"
```

### 1.2 Enable OIDC Issuer on AKS (if not already enabled)

```bash
az aks update \
  --resource-group $RESOURCE_GROUP \
  --name $AKS_CLUSTER_NAME \
  --enable-oidc-issuer \
  --enable-workload-identity
```

### 1.3 Get OIDC Issuer URL

```bash
export AKS_OIDC_ISSUER=$(az aks show \
  --resource-group $RESOURCE_GROUP \
  --name $AKS_CLUSTER_NAME \
  --query "oidcIssuerProfile.issuerUrl" \
  --output tsv)

echo "AKS OIDC Issuer: $AKS_OIDC_ISSUER"
```

### 1.4 Create Azure Managed Identity

```bash
az identity create \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME

export IDENTITY_CLIENT_ID=$(az identity show \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME \
  --query "clientId" \
  --output tsv)

export IDENTITY_OBJECT_ID=$(az identity show \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME \
  --query "principalId" \
  --output tsv)

echo "Identity Client ID: $IDENTITY_CLIENT_ID"
echo "Identity Object ID: $IDENTITY_OBJECT_ID"
```

### 1.5 Assign Azure RBAC Permissions

Grant the managed identity permissions to access Azure resources. For read-only access:

```bash
az role assignment create \
  --role "Reader" \
  --assignee-object-id $IDENTITY_OBJECT_ID \
  --assignee-principal-type ServicePrincipal \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

For broader access (adjust based on your security requirements):

```bash
az role assignment create \
  --role "Contributor" \
  --assignee-object-id $IDENTITY_OBJECT_ID \
  --assignee-principal-type ServicePrincipal \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

## Step 2: Establish Federated Identity Credential

Link the Kubernetes ServiceAccount to the Azure Managed Identity:

```bash
az identity federated-credential create \
  --name "azure-api-mcp-federated-credential" \
  --identity-name $IDENTITY_NAME \
  --resource-group $RESOURCE_GROUP \
  --issuer $AKS_OIDC_ISSUER \
  --subject "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
```

## Step 3: Build and Push Docker Image

### 3.1 Build the Image

From the repository root:

```bash
export CONTAINER_IMAGE="<your-registry>/azure-api-mcp:latest"
docker build -t $CONTAINER_IMAGE .
```

### 3.2 Push to Registry

```bash
docker push $CONTAINER_IMAGE
```

For Azure Container Registry (ACR):

```bash
export ACR_NAME="<your-acr-name>"
export CONTAINER_IMAGE="${ACR_NAME}.azurecr.io/azure-api-mcp:latest"
az acr build --registry $ACR_NAME --image azure-api-mcp:latest .
```

Attach ACR to AKS if needed:

```bash
az aks update \
  --resource-group $RESOURCE_GROUP \
  --name $AKS_CLUSTER_NAME \
  --attach-acr $ACR_NAME
```

## Step 4: Deploy to Kubernetes

### 4.1 Update deployment.yaml

The `deployment.yaml` uses environment variable references that match the variables you exported in previous steps:

```bash
# Verify your environment variables are set
echo "IDENTITY_CLIENT_ID: $IDENTITY_CLIENT_ID"
echo "TENANT_ID: $TENANT_ID"
echo "SUBSCRIPTION_ID: $SUBSCRIPTION_ID"
echo "CONTAINER_IMAGE: $CONTAINER_IMAGE"
```

If `TENANT_ID` is not set yet:

```bash
export TENANT_ID=$(az account show --query "tenantId" --output tsv)
echo "Tenant ID: $TENANT_ID"
```

If `CONTAINER_IMAGE` is not set (uses default `guwe/azure-api-mcp:latest`):

```bash
export CONTAINER_IMAGE="<your-registry>/azure-api-mcp:latest"
```

Use `envsubst` to substitute the variables in deployment.yaml:

```bash
envsubst < deployment.yaml | kubectl apply -f -
```

Alternatively, manually replace the placeholders in `deployment.yaml`:
- `$IDENTITY_CLIENT_ID` → your identity client ID
- `$TENANT_ID` → your Azure tenant ID
- `$SUBSCRIPTION_ID` → your subscription ID
- `$CONTAINER_IMAGE` → your container image

### 4.2 Apply the Configuration

If you used `envsubst`, the configuration is already applied. Otherwise:

```bash
envsubst < deployment.yaml | kubectl apply -f -
```

Or after manual editing:

```bash
kubectl apply -f deployment.yaml
```

This will create:
- ServiceAccount with Azure Workload Identity annotations
- Deployment running the azure-api-mcp server
- Service exposing the MCP server (ClusterIP)

## Step 5: Verify Deployment

### 5.1 Check Pod Status

```bash
kubectl get pods -l app=azure-api-mcp
```

Wait for the pod to be in `Running` state.

### 5.2 Check Logs

```bash
kubectl logs -l app=azure-api-mcp --tail=50
```

You should see:
```
Authentication setup completed successfully
Authentication validated successfully
Starting Azure API MCP server (version 1.0.0)
Streamable HTTP server listening on 0.0.0.0:8000
```

### 5.3 Test Authentication

Verify the pod can authenticate to Azure:

```bash
kubectl exec -it $(kubectl get pod -l app=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- az account show
```

You should see your subscription details in JSON format.

## Step 6: Access the MCP Server

### 6.1 Port Forward (for testing)

```bash
kubectl port-forward svc/azure-api-mcp 8000:8000
```

Now you can access the server at `http://localhost:8000`.

### 6.2 Test Health Endpoint

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"status":"healthy"}
```

### 6.3 Test MCP Tool (streamable-http transport)

#### Step 1: Initialize Session

First, initialize a session to get the session ID:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}}}' \
  -D /tmp/headers.txt
```

Extract the session ID from the response headers:

```bash
export MCP_SESSION_ID=$(grep -i 'mcp-session-id:' /tmp/headers.txt | awk '{print $2}' | tr -d '\r')
echo "Session ID: $MCP_SESSION_ID"
```

#### Step 2: List Available Tools

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $MCP_SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

#### Step 3: Call the Azure CLI Tool

Create a test request file `test-request.json`:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "call_az",
    "arguments": {
      "cli_command": "az account show"
    }
  }
}
```

Send the request with the session ID:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $MCP_SESSION_ID" \
  -d @test-request.json
```

Expected response format:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{...subscription details...}"
      }
    ]
  }
}
```

## Configuration Options

### Environment Variables in deployment.yaml

You can customize the deployment by modifying environment variables:

```yaml
env:
- name: AZURE_TENANT_ID
  value: "<YOUR_AZURE_TENANT_ID>"
- name: AZURE_CLIENT_ID
  value: "<YOUR_AZURE_CLIENT_ID>"
- name: AZURE_FEDERATED_TOKEN_FILE
  value: "/var/run/secrets/azure/tokens/azure-identity-token"
- name: AZURE_SUBSCRIPTION_ID
  value: "<YOUR_SUBSCRIPTION_ID>"
- name: AZ_AUTH_METHOD
  value: "workload-identity"
```

### Command Line Arguments

Modify the container `args` in deployment.yaml:

```yaml
args:
- "--transport"
- "streamable-http"
- "--host"
- "0.0.0.0"
- "--port"
- "8000"
- "--readonly=false"              # Enable write operations
- "--enable-security-policy"      # Enable security policy validation
- "--timeout"
- "300"                           # Command timeout in seconds
```

## Troubleshooting

### Pod Fails to Start

Check events:
```bash
kubectl describe pod -l app=azure-api-mcp
```

Common issues:
- Image pull errors: Verify ACR is attached to AKS or ImagePullSecrets are configured
- CrashLoopBackOff: Check logs for authentication errors

### Authentication Failures

Check the ServiceAccount annotation:
```bash
kubectl get serviceaccount azure-api-mcp-sa -o yaml
```

Verify the annotation exists:
```yaml
metadata:
  annotations:
    azure.workload.identity/client-id: "<YOUR_AZURE_CLIENT_ID>"
```

Check federated credential:
```bash
az identity federated-credential list \
  --identity-name $IDENTITY_NAME \
  --resource-group $RESOURCE_GROUP
```

Verify the subject matches:
```
system:serviceaccount:default:azure-api-mcp-sa
```

### Token Projection Issues

Verify the token is mounted:
```bash
kubectl exec -it $(kubectl get pod -l app=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- ls -la /var/run/secrets/azure/tokens/
```

Check token contents:
```bash
kubectl exec -it $(kubectl get pod -l app=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- cat /var/run/secrets/azure/tokens/azure-identity-token
```

### RBAC Permission Errors

Verify role assignments:
```bash
az role assignment list --assignee $IDENTITY_OBJECT_ID --all
```

Test specific commands inside the pod:
```bash
kubectl exec -it $(kubectl get pod -l app=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- az vm list
```

### Connection Timeout

Check network policies and service configuration:
```bash
kubectl get svc azure-api-mcp
kubectl get networkpolicies
```

## Security Considerations

1. **Least Privilege**: Grant only necessary Azure RBAC permissions
2. **Read-Only Mode**: Use `--readonly=true` (default) for read-only operations
3. **Security Policy**: Enable `--enable-security-policy` to block dangerous operations
4. **Network Policies**: Restrict pod network access using Kubernetes NetworkPolicies
5. **Namespace Isolation**: Deploy in a dedicated namespace with RBAC policies
6. **Token Expiration**: Workload Identity tokens auto-rotate (default: 24h)


## Clean Up

Remove Kubernetes resources:
```bash
kubectl delete -f deployment.yaml
```

Remove Azure resources:
```bash
az identity federated-credential delete \
  --name "azure-api-mcp-federated-credential" \
  --identity-name $IDENTITY_NAME \
  --resource-group $RESOURCE_GROUP

az identity delete \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME
```
