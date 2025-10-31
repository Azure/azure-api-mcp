package azcli

import (
	"github.com/mark3labs/mcp-go/mcp"
)

func RegisterCallAzTool(readOnlyMode bool, defaultSubscription string) mcp.Tool {
	description := generateToolDescription(readOnlyMode, defaultSubscription)

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

func generateToolDescription(readOnlyMode bool, defaultSubscription string) string {
	baseDesc := "Execute Azure CLI commands with security validation and policy enforcement.\n\n"

	if readOnlyMode {
		baseDesc += "Mode: READ-ONLY - Only read operations are allowed.\n\n"
	} else {
		baseDesc += "Mode: READ-WRITE - Both read and write operations are allowed (subject to policy).\n\n"
	}

	if defaultSubscription != "" {
		baseDesc += "Default Subscription: " + defaultSubscription + "\n\n"
	}

	baseDesc += "Examples:\n"
	baseDesc += "- List VMs: cli_command=\"az vm list --resource-group myRG\"\n"
	baseDesc += "- Show storage account (in a different subscription): cli_command=\"az storage account show --name myaccount --subscription <subscription-id>\"\n"
	baseDesc += "- List AKS clusters: cli_command=\"az aks list --resource-group myRG\"\n"
	baseDesc += "- Get AKS credentials: cli_command=\"az aks get-credentials --name myCluster --resource-group myRG\"\n"

	if !readOnlyMode {
		baseDesc += "- Create resource group: cli_command=\"az group create --name myRG --location eastus\"\n"
		baseDesc += "- Create AKS cluster: cli_command=\"az aks create --name myCluster --resource-group myRG --node-count 1\"\n"
	}

	return baseDesc
}
