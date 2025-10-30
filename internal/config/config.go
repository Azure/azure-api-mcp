package config

import (
	"fmt"
	"os"
	"time"

	flag "github.com/spf13/pflag"
)

type Config struct {
	ReadOnlyMode         bool
	EnableSecurityPolicy bool
	Timeout              int
	SecurityPolicyFile   string
	ReadOnlyPatternsFile string
	Transport            string
	Host                 string
	Port                 int
	LogLevel             string

	SkipAuthSetup       bool
	AuthMethod          string
	TenantID            string
	ClientID            string
	FederatedTokenFile  string
	ClientSecret        string
	DefaultSubscription string
}

func NewConfig() *Config {
	return &Config{
		ReadOnlyMode:         true,
		EnableSecurityPolicy: false,
		Timeout:              120,
		SecurityPolicyFile:   "",
		ReadOnlyPatternsFile: "",
		Transport:            "stdio",
		Host:                 "127.0.0.1",
		Port:                 8000,
		LogLevel:             "info",

		SkipAuthSetup: false,
		AuthMethod:    "auto",
	}
}

func (c *Config) ParseFlags() error {
	flag.BoolVar(&c.ReadOnlyMode, "readonly", c.ReadOnlyMode, "Enable read-only mode (only read operations allowed)")
	flag.BoolVar(&c.EnableSecurityPolicy, "enable-security-policy", c.EnableSecurityPolicy, "Enable security policy enforcement (deny list)")
	flag.IntVar(&c.Timeout, "timeout", c.Timeout, "Timeout for command execution in seconds")
	flag.StringVar(&c.SecurityPolicyFile, "security-policy-file", c.SecurityPolicyFile, "Path to security policy YAML file")
	flag.StringVar(&c.ReadOnlyPatternsFile, "readonly-patterns-file", c.ReadOnlyPatternsFile, "Path to read-only patterns YAML file")
	flag.StringVar(&c.Transport, "transport", c.Transport, "Transport mechanism (stdio, sse, streamable-http)")
	flag.StringVar(&c.Host, "host", c.Host, "Host to listen on (for non-stdio transport)")
	flag.IntVar(&c.Port, "port", c.Port, "Port to listen on (for non-stdio transport)")
	flag.StringVar(&c.LogLevel, "log-level", c.LogLevel, "Log level (debug, info, warn, error)")
	flag.StringVar(&c.AuthMethod, "auth-method", c.AuthMethod, "Authentication method (auto, workload-identity, managed-identity, service-principal)")

	showHelp := flag.BoolP("help", "h", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if *showHelp {
		fmt.Printf("Azure API MCP Server\n\nUsage:\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("Azure API MCP Server version 1.0.0\n")
		os.Exit(0)
	}

	c.loadAuthFromEnv()

	return c.Validate()
}

func (c *Config) loadAuthFromEnv() {
	if skip := os.Getenv("AZ_API_MCP_SKIP_AUTH_SETUP"); skip != "" {
		c.SkipAuthSetup = skip == "true" || skip == "1"
	}

	if c.AuthMethod == "auto" {
		if method := os.Getenv("AZ_AUTH_METHOD"); method != "" {
			c.AuthMethod = method
		}
	}

	if tenantID := os.Getenv("AZURE_TENANT_ID"); tenantID != "" {
		c.TenantID = tenantID
	}

	if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
		c.ClientID = clientID
	}

	if tokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE"); tokenFile != "" {
		c.FederatedTokenFile = tokenFile
	}

	if secret := os.Getenv("AZURE_CLIENT_SECRET"); secret != "" {
		c.ClientSecret = secret
	}

	if sub := os.Getenv("AZURE_SUBSCRIPTION_ID"); sub != "" {
		c.DefaultSubscription = sub
	}
}

func (c *Config) Validate() error {
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	validTransports := map[string]bool{
		"stdio":           true,
		"sse":             true,
		"streamable-http": true,
	}

	if !validTransports[c.Transport] {
		return fmt.Errorf("invalid transport: %s (must be stdio, sse, or streamable-http)", c.Transport)
	}

	return nil
}

func (c *Config) TimeoutDuration() time.Duration {
	return time.Duration(c.Timeout) * time.Second
}
