package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-api-mcp/internal/config"
	"github.com/Azure/azure-api-mcp/internal/logger"
	mcpserver "github.com/Azure/azure-api-mcp/internal/server"
	"github.com/Azure/azure-api-mcp/internal/version"
	"github.com/Azure/azure-api-mcp/pkg/azcli"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	cfg := config.NewConfig()
	if err := cfg.ParseFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := logger.SetLevel(cfg.LogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid log level '%s': %v\n", cfg.LogLevel, err)
		os.Exit(1)
	}
	logger.Debugf("Log level set to: %s", cfg.LogLevel)

	authTimeout := 30 * time.Second
	authCtx, authCancel := context.WithTimeout(context.Background(), authTimeout)
	defer authCancel()

	authConfig := azcli.AuthConfig{
		SkipSetup:           cfg.SkipAuthSetup,
		AuthMethod:          cfg.AuthMethod,
		TenantID:            cfg.TenantID,
		ClientID:            cfg.ClientID,
		FederatedTokenFile:  cfg.FederatedTokenFile,
		ClientSecret:        cfg.ClientSecret,
		DefaultSubscription: cfg.DefaultSubscription,
	}

	var authSetup azcli.AuthSetup
	if !cfg.SkipAuthSetup {
		authSetup = azcli.NewDefaultAuthSetup(authConfig)
		if err := authSetup.Setup(authCtx); err != nil {
			if authCtx.Err() == context.DeadlineExceeded {
				logger.Errorf("Authentication setup timed out after %v. This may indicate az CLI is waiting for interactive input or is not responding.", authTimeout)
				os.Exit(1)
			}
			logger.Errorf("Authentication setup failed: %v", err)
			os.Exit(1)
		}
		logger.Info("Authentication setup completed successfully")
	}

	authValidator := &azcli.DefaultAuthValidator{}
	if err := authValidator.ValidateAuth(authCtx); err != nil {
		if authCtx.Err() == context.DeadlineExceeded {
			logger.Errorf("Authentication validation timed out after %v. This may indicate az CLI is not configured or is waiting for interactive input.", authTimeout)
			os.Exit(1)
		}
		if cfg.SkipAuthSetup {
			logger.Errorf("Authentication validation failed: %v\nPlease run 'az login' manually first or set AZ_API_MCP_SKIP_AUTH_SETUP=false", err)
			os.Exit(1)
		} else {
			logger.Errorf("Authentication validation failed: %v", err)
			os.Exit(1)
		}
	}
	logger.Info("Authentication validated successfully")

	client, err := azcli.NewClient(azcli.ClientConfig{
		ReadOnlyMode:         cfg.ReadOnlyMode,
		EnableSecurityPolicy: cfg.EnableSecurityPolicy,
		Timeout:              cfg.TimeoutDuration(),
		WorkingDir:           "",
		SecurityPolicyFile:   cfg.SecurityPolicyFile,
		ReadOnlyPatternsFile: cfg.ReadOnlyPatternsFile,
		AuthSetup:            authSetup,
	})
	if err != nil {
		logger.Errorf("Failed to create Azure CLI client: %v", err)
		os.Exit(1)
	}

	mcpServer := server.NewMCPServer(
		"Azure API MCP",
		version.GetVersion(),
	)

	callAzTool := azcli.RegisterCallAzTool(cfg.ReadOnlyMode, cfg.DefaultSubscription)
	callAzHandler := mcpserver.CallAzHandler(client)
	mcpServer.AddTool(callAzTool, callAzHandler)

	logger.Infof("Starting Azure API MCP server (version %s)", version.GetVersion())
	if err := runServer(mcpServer, cfg); err != nil {
		logger.Errorf("Server error: %v", err)
		os.Exit(1)
	}
}

func runServer(mcpServer *server.MCPServer, cfg *config.Config) error {
	if cfg.Transport != "stdio" {
		return fmt.Errorf("unsupported transport %q: only stdio is supported", cfg.Transport)
	}

	logger.Info("Listening for requests on STDIO...")
	return server.ServeStdio(mcpServer)
}
