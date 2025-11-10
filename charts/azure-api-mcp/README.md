# Azure API MCP Helm Chart

A Helm chart for deploying Azure API MCP server on Kubernetes with Azure Workload Identity support.

## Overview

This Helm chart deploys the Azure API MCP server on a Kubernetes cluster, providing a secure gateway for LLM agents to interact with Azure resources through the Azure CLI. The chart is optimized for Azure Kubernetes Service (AKS) with Workload Identity for passwordless authentication.

**Default Configuration:**
- **Transport**: `streamable-http` (HTTP-based MCP protocol)
- **Read-Only Mode**: `false` (write operations allowed)
- **Authentication**: `workload-identity` (requires Azure setup before installation)
- **Replicas**: `2` (for high availability)
- **Port**: `8000`

## Prerequisites

- Kubernetes cluster (AKS recommended)
- Helm 3.x
- Azure CLI installed and authenticated
- AKS cluster with OIDC Issuer enabled (for Workload Identity)
- Permissions to create Azure Managed Identities and role assignments

## Deployment Guide

Follow these steps in order to deploy Azure API MCP:

### Step 1: Enable OIDC on AKS

```bash
export RESOURCE_GROUP="<your-resource-group>"
export AKS_CLUSTER_NAME="<your-aks-cluster>"

# Enable OIDC Issuer and Workload Identity
az aks update \
  --resource-group $RESOURCE_GROUP \
  --name $AKS_CLUSTER_NAME \
  --enable-oidc-issuer \
  --enable-workload-identity

# Get OIDC Issuer URL
export AKS_OIDC_ISSUER=$(az aks show \
  --resource-group $RESOURCE_GROUP \
  --name $AKS_CLUSTER_NAME \
  --query "oidcIssuerProfile.issuerUrl" \
  --output tsv)

echo "OIDC Issuer: $AKS_OIDC_ISSUER"
```

### Step 2: Create Azure Managed Identity

```bash
export IDENTITY_NAME="azure-api-mcp-identity"
export LOCATION="<your-location>"

# Create Managed Identity
az identity create \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME \
  --location $LOCATION

# Get Identity Client ID and Principal ID
export IDENTITY_CLIENT_ID=$(az identity show \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME \
  --query "clientId" \
  --output tsv)

export IDENTITY_PRINCIPAL_ID=$(az identity show \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME \
  --query "principalId" \
  --output tsv)

echo "Identity Client ID: $IDENTITY_CLIENT_ID"
echo "Identity Principal ID: $IDENTITY_PRINCIPAL_ID"
```

### Step 3: Configure Azure RBAC Permissions

The Azure Managed Identity needs appropriate RBAC roles to access Azure resources. See [Azure RBAC Configuration](#azure-rbac-configuration) section below for detailed permission options.

Quick example (Reader role):

```bash
export SUBSCRIPTION_ID=$(az account show --query id --output tsv)

az role assignment create \
  --role "Reader" \
  --assignee-object-id $IDENTITY_PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

### Step 4: Create Federated Identity Credential

Link the Kubernetes ServiceAccount to the Azure Managed Identity:

```bash
export SERVICE_ACCOUNT_NAMESPACE="default"
export SERVICE_ACCOUNT_NAME="azure-mcp-azure-api-mcp"  # Format: <release-name>-<chart-name>

# Create federated credential
az identity federated-credential create \
  --name "azure-api-mcp-federated-credential" \
  --identity-name $IDENTITY_NAME \
  --resource-group $RESOURCE_GROUP \
  --issuer $AKS_OIDC_ISSUER \
  --subject "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}" \
  --audience api://AzureADTokenExchange
```

**Note**: The ServiceAccount name follows Helm's naming convention: `<release-name>-<chart-name>`. Adjust if using custom release name or `fullnameOverride`.

**Important**: You must create the federated credential BEFORE installing the Helm chart, otherwise authentication will fail.

### Step 5: Install Helm Chart

```bash
export TENANT_ID=$(az account show --query tenantId --output tsv)

helm install azure-mcp ./charts/azure-api-mcp \
  --set auth.azure.tenantId=$TENANT_ID \
  --set auth.azure.clientId=$IDENTITY_CLIENT_ID \
  --set auth.azure.subscriptionId=$SUBSCRIPTION_ID
```

### Step 6: Verify Deployment

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=azure-api-mcp

# Check logs
kubectl logs -l app.kubernetes.io/name=azure-api-mcp --tail=50

# Verify authentication
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- az account show
```

## Azure RBAC Configuration

The Azure Managed Identity needs appropriate RBAC roles to access Azure resources. Configure based on your requirements:

### Granting Permissions

Example: Grant Reader role at subscription level for read-only access:

```bash
export SUBSCRIPTION_ID=$(az account show --query id --output tsv)

az role assignment create \
  --role "Reader" \
  --assignee-object-id $IDENTITY_PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

For write operations (when `security.readonly=false`), use `Contributor` role or create a custom role with specific permissions.

For resource group-scoped access, change the scope:
```bash
--scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<resource-group-name>"
```

### Best Practices

- Start with minimal permissions (Reader role)
- Prefer resource group-level scope over subscription-level
- Use custom roles for fine-grained control
- Enable security policy with `--enable-security-policy`
- Regularly audit role assignments

## Configuration Examples

Once you have completed the deployment steps above, you can customize your installation:

### Enable Read-Only Mode

```bash
helm upgrade azure-mcp ./charts/azure-api-mcp \
  --reuse-values \
  --set security.readonly=true
```

### Enable Security Policy

```bash
helm upgrade azure-mcp ./charts/azure-api-mcp \
  --reuse-values \
  --set security.enableSecurityPolicy=true
```

### Change Image

```bash
helm upgrade azure-mcp ./charts/azure-api-mcp \
  --reuse-values \
  --set image.repository=myregistry.azurecr.io/azure-api-mcp \
  --set image.tag=v1.0.0
```

### Scale Replicas

```bash
helm upgrade azure-mcp ./charts/azure-api-mcp \
  --reuse-values \
  --set replicaCount=3
```

## Configuration Reference

### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |

### Image Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/azure/azure-api-mcp` |
| `image.pullPolicy` | Image pull policy | `Always` |
| `image.tag` | Image tag (defaults to chart appVersion) | `"latest"` |
| `imagePullSecrets` | Image pull secrets | `[]` |

### Transport Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `transport` | Transport mechanism (`stdio`, `sse`, `streamable-http`) | `streamable-http` |
| `port` | Server port | `8000` |

### Authentication Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.method` | Auth method (`workload-identity`, `managed-identity`, `service-principal`, `auto`) | `workload-identity` |
| `auth.skipSetup` | Skip automatic auth setup | `false` |
| `auth.azure.tenantId` | Azure Tenant ID | `""` |
| `auth.azure.clientId` | Azure Client ID | `""` |
| `auth.azure.subscriptionId` | Azure Subscription ID | `""` |

### Security Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.readonly` | Enable read-only mode | `false` |
| `security.enableSecurityPolicy` | Enable security policy enforcement | `false` |
| `security.timeout` | Command timeout in seconds | `120` |
| `security.customSecurityPolicyYaml` | Custom security policy YAML content | `""` |
| `security.customReadonlyPatternsYaml` | Custom readonly patterns YAML content | `""` |

### ServiceAccount Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `serviceAccount.annotations` | ServiceAccount annotations | `{}` |
| `serviceAccount.name` | ServiceAccount name (generated if empty) | `""` |

### Workload Identity Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `workloadIdentity.enabled` | Enable Azure Workload Identity | `true` |

### Service Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8000` |
| `service.targetPort` | Target port | `8000` |
| `service.annotations` | Service annotations | `{}` |

### Resource Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

### Health Check Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `livenessProbe` | Liveness probe configuration | See `values.yaml` |
| `readinessProbe` | Readiness probe configuration | See `values.yaml` |

### Other Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `podAnnotations` | Pod annotations | `{}` |
| `podSecurityContext` | Pod security context | `{}` |
| `securityContext` | Container security context | `{}` |

## Advanced Configuration

### Custom Security Policy

Create a custom security policy to block specific operations:

```yaml
# custom-values.yaml
security:
  enableSecurityPolicy: true
  customSecurityPolicyYaml: |
    deny_patterns:
      - pattern: "az.*delete.*"
        reason: "Delete operations are not allowed"
      - pattern: "az.*logout.*"
        reason: "Logout not permitted"
```

Install with custom values:

```bash
helm install azure-mcp ./charts/azure-api-mcp -f custom-values.yaml
```

### Custom Readonly Patterns

Override the default readonly patterns:

```yaml
# custom-values.yaml
security:
  readonly: true
  customReadonlyPatternsYaml: |
    allow_patterns:
      - "^az account show"
      - "^az account list"
      - "^az vm list"
      - "^az vm show"
```

### Multiple Resource Groups

Deploy separate instances for different resource groups:

```bash
# Instance for production resources
helm install azure-mcp-prod ./charts/azure-api-mcp \
  --namespace prod \
  --create-namespace \
  --set auth.azure.clientId=$PROD_CLIENT_ID

# Instance for development resources
helm install azure-mcp-dev ./charts/azure-api-mcp \
  --namespace dev \
  --create-namespace \
  --set auth.azure.clientId=$DEV_CLIENT_ID
```

## Accessing the Service

### Port Forward (Development)

```bash
kubectl port-forward svc/azure-mcp-azure-api-mcp 8000:8000

# Test health endpoint
curl http://localhost:8000/health

# Test MCP endpoint (requires session initialization)
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}'
```

### Using with GitHub Copilot

Configure `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "azure-api-mcp": {
      "url": "http://localhost:8000/mcp",
      "type": "http"
    }
  }
}
```

Then port-forward and use Copilot to interact with Azure resources.

## Troubleshooting

### Pod Not Starting

Check pod events and logs:

```bash
kubectl describe pod -l app.kubernetes.io/name=azure-api-mcp
kubectl logs -l app.kubernetes.io/name=azure-api-mcp --tail=100
```

Common issues:
- **Image pull errors**: Verify image repository and credentials
- **CrashLoopBackOff**: Check authentication configuration

### Authentication Failures

Verify ServiceAccount configuration:

```bash
kubectl get serviceaccount azure-mcp-azure-api-mcp -o yaml
```

Check annotations:
```yaml
metadata:
  annotations:
    azure.workload.identity/client-id: "<client-id>"
```

Verify federated credential:

```bash
az identity federated-credential list \
  --identity-name $IDENTITY_NAME \
  --resource-group $RESOURCE_GROUP \
  --output table
```

### RBAC Permission Errors

Test permissions inside the pod:

```bash
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- az vm list

# If permission denied, check role assignments
az role assignment list --assignee $IDENTITY_PRINCIPAL_ID --all
```

### Token Projection Issues

Verify token is mounted:

```bash
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=azure-api-mcp -o jsonpath='{.items[0].metadata.name}') -- ls -la /var/run/secrets/azure/tokens/
```

Check OIDC Issuer configuration:

```bash
az aks show \
  --resource-group $RESOURCE_GROUP \
  --name $AKS_CLUSTER_NAME \
  --query "oidcIssuerProfile"
```

## Upgrading

```bash
# Upgrade with new values
helm upgrade azure-mcp ./charts/azure-api-mcp \
  --set image.tag=v1.1.0

# View release history
helm history azure-mcp

# Rollback if needed
helm rollback azure-mcp 1
```

## Uninstalling

```bash
# Remove Helm release
helm uninstall azure-mcp

# Clean up Azure resources
az identity federated-credential delete \
  --name "azure-api-mcp-federated-credential" \
  --identity-name $IDENTITY_NAME \
  --resource-group $RESOURCE_GROUP

az identity delete \
  --resource-group $RESOURCE_GROUP \
  --name $IDENTITY_NAME
```

## Security Best Practices

1. **Use Workload Identity**: Avoid storing credentials in Kubernetes Secrets
2. **Enable Read-Only Mode**: Set `security.readonly=true` for monitoring use cases
3. **Enable Security Policy**: Set `security.enableSecurityPolicy=true` to block dangerous operations
4. **Scope RBAC Permissions**: Grant minimal Azure RBAC permissions required
5. **Use Resource Group Scoping**: Assign permissions at resource group level instead of subscription
6. **Network Policies**: Deploy NetworkPolicies to restrict pod network access
7. **Regular Audits**: Review Azure RBAC assignments and Kubernetes configurations periodically

## References

- [Azure Workload Identity Documentation](https://azure.github.io/azure-workload-identity/)
- [Azure RBAC Documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/)
- [AKS OIDC Issuer](https://docs.microsoft.com/en-us/azure/aks/use-oidc-issuer)
- [Project Repository](https://github.com/Azure/azure-api-mcp)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)

## Support

For issues and questions:
- GitHub Issues: https://github.com/Azure/azure-api-mcp/issues
- Documentation: https://github.com/Azure/azure-api-mcp/tree/main/docs
