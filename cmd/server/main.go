package main

import (
	"context"
	"fmt"
	"net/http"
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
	switch cfg.Transport {
	case "stdio":
		logger.Info("Listening for requests on STDIO...")
		return server.ServeStdio(mcpServer)

	case "sse":
		addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
		baseURL := fmt.Sprintf("http://%s", addr)

		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		})

		customServer := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		sseServer := server.NewSSEServer(
			mcpServer,
			server.WithBaseURL(baseURL),
			server.WithHTTPServer(customServer),
		)

		logger.Infof("SSE server listening on %s", addr)
		logger.Infof("Base URL: %s", baseURL)
		logger.Infof("SSE endpoint available at: http://%s/sse", addr)
		logger.Infof("Message endpoint available at: http://%s/message", addr)
		logger.Infof("Health check available at: http://%s/health", addr)
		logger.Info("Connect to /sse for real-time events, send JSON-RPC to /message")

		return sseServer.Start(addr)

	case "streamable-http":
		addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		})

		customServer := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		streamableServer := server.NewStreamableHTTPServer(
			mcpServer,
			server.WithStreamableHTTPServer(customServer),
		)

		mux.Handle("/mcp", streamableServer)

		logger.Infof("Streamable HTTP server listening on %s", addr)
		logger.Infof("MCP endpoint available at: http://%s/mcp", addr)
		logger.Infof("Health check available at: http://%s/health", addr)
		logger.Info("Send POST requests to /mcp to initialize session and obtain Mcp-Session-Id")

		return customServer.ListenAndServe()

	default:
		return fmt.Errorf("invalid transport type: %s (must be 'stdio', 'sse', or 'streamable-http')", cfg.Transport)
	}
}
