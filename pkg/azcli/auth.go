package azcli

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

type AuthSetup interface {
	Setup(ctx context.Context) error
}

type DefaultAuthSetup struct {
	config AuthConfig
}

func NewDefaultAuthSetup(config AuthConfig) *DefaultAuthSetup {
	return &DefaultAuthSetup{
		config: config,
	}
}

func (s *DefaultAuthSetup) Setup(ctx context.Context) error {
	if s.config.SkipSetup {
		return nil
	}

	authMethod := s.config.AuthMethod
	if authMethod == "" || authMethod == "auto" {
		authMethod = s.detectAuthMethod()
	}

	switch authMethod {
	case "workload-identity":
		return s.setupWorkloadIdentity(ctx)
	case "managed-identity":
		return s.setupManagedIdentity(ctx)
	case "service-principal":
		return s.setupServicePrincipal(ctx)
	case "":
		log.Println("[INFO] No automatic authentication method detected. Assuming user is already logged in with 'az login'.")
		return nil
	default:
		return fmt.Errorf("unknown auth method: %s (supported: workload-identity, managed-identity, service-principal)", authMethod)
	}
}

func (s *DefaultAuthSetup) setupWorkloadIdentity(ctx context.Context) error {
	if s.config.FederatedTokenFile == "" {
		return fmt.Errorf("AZURE_FEDERATED_TOKEN_FILE not set")
	}

	tokenBytes, err := os.ReadFile(s.config.FederatedTokenFile)
	if err != nil {
		return fmt.Errorf("failed to read federated token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	cmd := exec.CommandContext(ctx, "az", "login",
		"--federated-token", token,
		"--service-principal",
		"-u", s.config.ClientID,
		"-t", s.config.TenantID,
		"--output", "json",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("workload identity login failed: %w, output: %s", err, string(output))
	}

	return s.setDefaultSubscription(ctx)
}

func (s *DefaultAuthSetup) setupManagedIdentity(ctx context.Context) error {
	args := []string{"login", "--identity", "--output", "json"}

	if s.config.ClientID != "" {
		args = append(args, "-u", s.config.ClientID)
	}

	cmd := exec.CommandContext(ctx, "az", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("managed identity login failed: %w, output: %s", err, string(output))
	}

	return s.setDefaultSubscription(ctx)
}

func (s *DefaultAuthSetup) setupServicePrincipal(ctx context.Context) error {
	if s.config.ClientSecret == "" {
		return fmt.Errorf("AZURE_CLIENT_SECRET not set")
	}

	cmd := exec.CommandContext(ctx, "az", "login",
		"--service-principal",
		"-u", s.config.ClientID,
		"-p", s.config.ClientSecret,
		"--tenant", s.config.TenantID,
		"--output", "json",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("service principal login failed: %w, output: %s", err, string(output))
	}

	return s.setDefaultSubscription(ctx)
}

func (s *DefaultAuthSetup) setDefaultSubscription(ctx context.Context) error {
	if s.config.DefaultSubscription == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, "az", "account", "set",
		"--subscription", s.config.DefaultSubscription,
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set subscription: %w", err)
	}

	return nil
}

func (s *DefaultAuthSetup) detectAuthMethod() string {
	if s.config.FederatedTokenFile != "" && s.config.ClientID != "" && s.config.TenantID != "" {
		return "workload-identity"
	}

	if s.config.ClientSecret != "" && s.config.ClientID != "" && s.config.TenantID != "" {
		return "service-principal"
	}

	if os.Getenv("MSI_ENDPOINT") != "" || os.Getenv("IDENTITY_ENDPOINT") != "" {
		return "managed-identity"
	}

	return ""
}

type AuthValidator interface {
	ValidateAuth(ctx context.Context) error
}

type DefaultAuthValidator struct{}

func (v *DefaultAuthValidator) ValidateAuth(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "az", "account", "show", "--output", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("azure CLI authentication failed: %w, output: %s", err, string(output))
	}
	return nil
}
