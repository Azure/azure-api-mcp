package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-api-mcp/internal/logger"
	"github.com/Azure/azure-api-mcp/pkg/azcli"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func CallAzHandler(client azcli.Client) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cliCommand, err := request.RequireString("cli_command")
		if err != nil {
			logger.Warnf("Missing cli_command parameter: %v", err)
			return mcp.NewToolResultError("cli_command is required"), nil
		}

		timeout := time.Duration(request.GetFloat("timeout", 120)) * time.Second
		logger.Debugf("Executing command: %s (timeout: %v)", cliCommand, timeout)

		execCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		if err := client.ValidateCommand(cliCommand); err != nil {
			logger.Warnf("Command validation failed: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("validation error: %v", err)), nil
		}

		result, err := client.ExecuteCommand(execCtx, cliCommand)
		if err != nil {
			logger.Errorf("Command execution failed: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("execution error: %v", err)), nil
		}

		if result.ExitCode != 0 {
			logger.Warnf("Command failed with exit code %d: %s", result.ExitCode, result.Error)
			return mcp.NewToolResultError(fmt.Sprintf("command failed (exit code %d): %s", result.ExitCode, result.Error)), nil
		}

		logger.Debugf("Command executed successfully (duration: %v)", result.Duration)

		return mcp.NewToolResultText(string(result.Output)), nil
	}
}
