# Azure API MCP

A secure MCP (Model Context Protocol) server that provides controlled access to Azure CLI commands for LLM agents.

## Features

- **Multi-layer Security Validation**: Basic security checks, configurable security policy, and read-only mode
- **Flexible Authentication**: Support for workload identity, managed identity, service principal, and existing sessions
- **Embedded Configuration**: Config files embedded in binary, no external dependencies required
- **Multiple Transport Modes**: stdio, SSE, and streamable-http
- **Timeout Control**: Configurable command execution timeouts
- **Structured Error Handling**: Detailed error information and types

## Quick Start

### Prerequisites

- Go 1.24 or higher
- Azure CLI (`az`) installed and in PATH

### Installation

```bash
go build -o bin/azure-api-mcp ./cmd/server
```

### Running

```bash
# Default mode (stdio transport, read-only)
./bin/azure-api-mcp

# Non-read-only mode
./bin/azure-api-mcp --readonly=false

# With security policy
./bin/azure-api-mcp --enable-security-policy --security-policy-file configs/security-policy.yaml

# SSE transport mode
./bin/azure-api-mcp --transport sse --host 0.0.0.0 --port 8000
```

## Authentication

The server supports multiple Azure authentication methods:

### Auto-detection (default)

Tries in the following order:
1. Workload Identity
2. Managed Identity
3. Existing Azure CLI session

### Explicit Configuration

Specify authentication method via environment variables:

```bash
# Workload Identity
AZ_AUTH_METHOD=workload-identity \
  AZURE_TENANT_ID=xxx \
  AZURE_CLIENT_ID=xxx \
  AZURE_FEDERATED_TOKEN_FILE=/path/to/token \
  ./bin/azure-api-mcp

# Managed Identity
AZ_AUTH_METHOD=managed-identity ./bin/azure-api-mcp

# Service Principal
AZ_AUTH_METHOD=service-principal \
  AZURE_TENANT_ID=xxx \
  AZURE_CLIENT_ID=xxx \
  AZURE_CLIENT_SECRET=xxx \
  ./bin/azure-api-mcp

# Skip automatic authentication setup
AZ_API_MCP_SKIP_AUTH_SETUP=true ./bin/azure-api-mcp
```

## MCP Tool

### call_az

The primary tool for executing Azure CLI commands.

**Parameters:**
- `cli_command` (string, required): The Azure CLI command to execute
- `timeout` (number, optional): Command timeout in seconds, default 120

**Examples:**
- Show storage account: `cli_command="az storage account show --name myaccount"`
- List AKS clusters: `cli_command="az aks list"`
- With timeout: `cli_command="az vm list", timeout=60`

## Configuration Options

### Command Line Flags

```bash
# Transport mode
--transport string          Transport mode: stdio, sse, streamable-http (default "stdio")
--host string              Host to listen on for non-stdio transport (default "127.0.0.1")
--port int                 Port to listen on for non-stdio transport (default 8000)

# Security configuration
--readonly                 Enable read-only mode (default true)
--readonly-patterns-file   Custom read-only patterns file
--enable-security-policy   Enable security policy validation
--security-policy-file     Custom security policy file

# Authentication
--auth-method string       Authentication method: auto, workload-identity, managed-identity, service-principal (default "auto")

# Other options
--timeout int              Timeout for command execution in seconds (default 120)
--log-level string         Log level: debug, info, warn, error (default "info")
```

### Environment Variables

```bash
# Authentication
AZ_AUTH_METHOD=auto|workload-identity|managed-identity|service-principal
AZ_API_MCP_SKIP_AUTH_SETUP=true|false
AZURE_TENANT_ID=xxx
AZURE_CLIENT_ID=xxx
AZURE_CLIENT_SECRET=xxx
AZURE_FEDERATED_TOKEN_FILE=/path/to/token
AZURE_SUBSCRIPTION_ID=xxx
```

## Security Architecture

### Three-tier Validation System

1. **Basic Security** (always enforced)
   - Must start with "az "
   - Blocks shell operators: `|`, `>`, `<`, `&&`, `||`, `;`, `$`, `` ` ``, newlines
   - Prevents path traversal: `../` and `..\`

2. **Security Policy** (optional, via `--enable-security-policy`)
   - Deny-list defined in `configs/security-policy.yaml`
   - Blocks dangerous operations such as:
     ```yaml
     - az login
     - az logout
     - az group delete
     - az ad user delete
     ```

3. **Read-Only Mode** (default behavior)
   - Allow-list defined in `configs/readonly-operations.yaml`
   - Only permits safe read operations: list, show, get-*, check-*, describe, query
   - Must explicitly disable (`--readonly=false`) for write operations

## Development

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./pkg/azcli/...

# Run with verbose output
go test -v ./...

# Run integration tests (requires Azure CLI setup)
go test -v -tags=integration ./pkg/azcli/...
```

### Code Quality

```bash
# Format code
go fmt ./...

# Static analysis
go vet ./...
staticcheck ./...
```

## Contributing

Contributions are welcome! Please see [SECURITY.md](SECURITY.md) for security issue reporting guidelines.
