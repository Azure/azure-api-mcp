package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Azure/azure-api-mcp/internal/config"
	mcpserver "github.com/Azure/azure-api-mcp/internal/server"
	"github.com/Azure/azure-api-mcp/internal/version"
	"github.com/Azure/azure-api-mcp/pkg/azcli"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	cfg := config.NewConfig()
	if err := cfg.ParseFlags(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	authTimeout := 30 * time.Second
	authCtx, authCancel := context.WithTimeout(context.Background(), authTimeout)
	defer authCancel()

	if !cfg.SkipAuthSetup {
		authConfig := azcli.AuthConfig{
			SkipSetup:           cfg.SkipAuthSetup,
			AuthMethod:          cfg.AuthMethod,
			TenantID:            cfg.TenantID,
			ClientID:            cfg.ClientID,
			FederatedTokenFile:  cfg.FederatedTokenFile,
			ClientSecret:        cfg.ClientSecret,
			DefaultSubscription: cfg.DefaultSubscription,
		}

		authSetup := azcli.NewDefaultAuthSetup(authConfig)
		if err := authSetup.Setup(authCtx); err != nil {
			if authCtx.Err() == context.DeadlineExceeded {
				log.Fatalf("Authentication setup timed out after %v. This may indicate az CLI is waiting for interactive input or is not responding.", authTimeout)
			}
			log.Fatalf("Authentication setup failed: %v", err)
		}
		log.Printf("Authentication setup completed successfully")
	}

	authValidator := &azcli.DefaultAuthValidator{}
	if err := authValidator.ValidateAuth(authCtx); err != nil {
		if authCtx.Err() == context.DeadlineExceeded {
			log.Fatalf("Authentication validation timed out after %v. This may indicate az CLI is not configured or is waiting for interactive input.", authTimeout)
		}
		if cfg.SkipAuthSetup {
			log.Fatalf("Authentication validation failed: %v\nPlease run 'az login' manually first or set AZ_API_MCP_SKIP_AUTH_SETUP=false", err)
		} else {
			log.Fatalf("Authentication validation failed: %v", err)
		}
	}
	log.Printf("Authentication validated successfully")

	client, err := azcli.NewClient(azcli.ClientConfig{
		ReadOnlyMode:         cfg.ReadOnlyMode,
		EnableSecurityPolicy: cfg.EnableSecurityPolicy,
		Timeout:              cfg.TimeoutDuration(),
		WorkingDir:           "",
		SecurityPolicyFile:   cfg.SecurityPolicyFile,
		ReadOnlyPatternsFile: cfg.ReadOnlyPatternsFile,
	})
	if err != nil {
		log.Fatalf("Failed to create Azure CLI client: %v", err)
	}

	mcpServer := server.NewMCPServer(
		"Azure API MCP",
		version.GetVersion(),
	)

	callAzTool := azcli.RegisterCallAzTool(cfg.ReadOnlyMode, cfg.DefaultSubscription)
	callAzHandler := mcpserver.CallAzHandler(client)
	mcpServer.AddTool(callAzTool, callAzHandler)

	log.Printf("Starting Azure API MCP server (version %s)", version.GetVersion())
	if err := runServer(mcpServer, cfg); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func runServer(mcpServer *server.MCPServer, cfg *config.Config) error {
	switch cfg.Transport {
	case "stdio":
		log.Printf("Listening for requests on STDIO...")
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

		log.Printf("SSE server listening on %s", addr)
		log.Printf("Base URL: %s", baseURL)
		log.Printf("SSE endpoint available at: http://%s/sse", addr)
		log.Printf("Message endpoint available at: http://%s/message", addr)
		log.Printf("Health check available at: http://%s/health", addr)
		log.Printf("Connect to /sse for real-time events, send JSON-RPC to /message")

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

		log.Printf("Streamable HTTP server listening on %s", addr)
		log.Printf("MCP endpoint available at: http://%s/mcp", addr)
		log.Printf("Health check available at: http://%s/health", addr)
		log.Printf("Send POST requests to /mcp to initialize session and obtain Mcp-Session-Id")

		return customServer.ListenAndServe()

	default:
		return fmt.Errorf("invalid transport type: %s (must be 'stdio', 'sse', or 'streamable-http')", cfg.Transport)
	}
}
