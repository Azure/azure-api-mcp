package azcli

import (
	"github.com/mark3labs/mcp-go/mcp"
)

func NewNoOpSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		Version: "1.0",
		Policy: PolicyRules{
			DenyList: []string{},
		},
	}
}

func RegisterCallAzTool(readOnlyMode bool) mcp.Tool {
	description := generateToolDescription(readOnlyMode)

	return mcp.NewTool("call_az",
		mcp.WithDescription(description),
		mcp.WithString("cli_command",
			mcp.Required(),
			mcp.Description("The Azure CLI command to execute (e.g., 'az vm list --resource-group myRG')"),
		),
		mcp.WithNumber("timeout",
			mcp.Description("Optional timeout in seconds (default: 120)"),
		),
	)
}

func generateToolDescription(readOnlyMode bool) string {
	baseDesc := "Execute Azure CLI commands with security validation and policy enforcement.\n\n"

	if readOnlyMode {
		baseDesc += "Mode: READ-ONLY - Only read operations are allowed.\n\n"
	} else {
		baseDesc += "Mode: READ-WRITE - Both read and write operations are allowed (subject to policy).\n\n"
	}

	baseDesc += "Security Features:\n"
	baseDesc += "- Command validation and sanitization\n"
	baseDesc += "- Security policy enforcement (deny/allow/elicit lists)\n"
	baseDesc += "- File system access controls\n"
	baseDesc += "- Azure RBAC enforcement\n\n"

	baseDesc += "Examples:\n"
	baseDesc += "- List VMs: cli_command=\"az vm list --resource-group myRG\"\n"
	baseDesc += "- Show storage account: cli_command=\"az storage account show --name myaccount\"\n"

	if !readOnlyMode {
		baseDesc += "- Create resource group: cli_command=\"az group create --name myRG --location eastus\"\n"
	}

	return baseDesc
}
