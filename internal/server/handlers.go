package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-api-mcp/pkg/azcli"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func CallAzHandler(client azcli.Client) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cliCommand, err := request.RequireString("cli_command")
		if err != nil {
			return mcp.NewToolResultError("cli_command is required"), nil
		}

		timeout := time.Duration(request.GetFloat("timeout", 120)) * time.Second

		execCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		if err := client.ValidateCommand(cliCommand); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("validation error: %v", err)), nil
		}

		result, err := client.ExecuteCommand(execCtx, cliCommand)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("execution error: %v", err)), nil
		}

		if result.ExitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("command failed (exit code %d): %s", result.ExitCode, result.Error)), nil
		}

		return mcp.NewToolResultText(string(result.Output)), nil
	}
}
