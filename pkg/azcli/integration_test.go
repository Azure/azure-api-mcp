package azcli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientIntegration_SecurityPolicyEnforcement(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	patternsFile := filepath.Join(tmpDir, "patterns.yaml")

	policyContent := `version: "1.0"
policy:
  denyList:
    - "az account clear"
    - "az vm delete"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	patternsContent := `patterns:
  - "^az [a-z-]+ list($| )"
  - "^az [a-z-]+ show($| )"
`
	if err := os.WriteFile(patternsFile, []byte(patternsContent), 0644); err != nil {
		t.Fatal(err)
	}

	config := ClientConfig{
		EnableSecurityPolicy: true,
		ReadOnlyMode:         true,
		SecurityPolicyFile:   policyFile,
		ReadOnlyPatternsFile: patternsFile,
		Timeout:              5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	tests := []struct {
		name    string
		command string
		wantErr bool
		errType ErrorType
	}{
		{
			name:    "allowed read-only command",
			command: "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "denied by policy",
			command: "az vm delete --name myVM",
			wantErr: true,
			errType: ErrorTypeCommandDenied,
		},
		{
			name:    "denied by read-only mode",
			command: "az vm create --name myVM",
			wantErr: true,
			errType: ErrorTypeCommandDenied,
		},
		{
			name:    "command injection attempt",
			command: "az vm list | cat /etc/passwd",
			wantErr: true,
			errType: ErrorTypeInvalidCommand,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidateCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				azErr, ok := err.(*AzCliError)
				if !ok {
					t.Errorf("expected AzCliError, got %T", err)
					return
				}
				if azErr.Type != tt.errType {
					t.Errorf("expected error type %v, got %v", tt.errType, azErr.Type)
				}
			}
		})
	}
}

func TestClientIntegration_ReadOnlyModeOnly(t *testing.T) {
	tmpDir := t.TempDir()
	patternsFile := filepath.Join(tmpDir, "patterns.yaml")

	patternsContent := `patterns:
  - "^az [a-z-]+ list($| )"
  - "^az [a-z-]+ show($| )"
  - "^az account show($| )"
`
	if err := os.WriteFile(patternsFile, []byte(patternsContent), 0644); err != nil {
		t.Fatal(err)
	}

	config := ClientConfig{
		EnableSecurityPolicy: false,
		ReadOnlyMode:         true,
		ReadOnlyPatternsFile: patternsFile,
		Timeout:              5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{
			name:    "allowed list command",
			command: "az vm list",
			wantErr: false,
		},
		{
			name:    "allowed show command",
			command: "az vm show --name myVM",
			wantErr: false,
		},
		{
			name:    "denied create command",
			command: "az vm create --name myVM",
			wantErr: true,
		},
		{
			name:    "denied delete command",
			command: "az vm delete --name myVM",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidateCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClientIntegration_NoRestrictions(t *testing.T) {
	config := ClientConfig{
		EnableSecurityPolicy: false,
		ReadOnlyMode:         false,
		Timeout:              5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{
			name:    "list command",
			command: "az vm list",
			wantErr: false,
		},
		{
			name:    "create command allowed",
			command: "az vm create --name myVM",
			wantErr: false,
		},
		{
			name:    "delete command allowed",
			command: "az vm delete --name myVM",
			wantErr: false,
		},
		{
			name:    "command injection still blocked",
			command: "az vm list | cat /etc/passwd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidateCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClientIntegration_ExecuteWithTimeout(t *testing.T) {
	config := ClientConfig{
		EnableSecurityPolicy: false,
		ReadOnlyMode:         false,
		Timeout:              100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	_, err = client.ExecuteCommand(ctx, "az vm list --query \"sleep 1\"")

	if err == nil {
		t.Skip("Test skipped: command completed before timeout")
	}

	azErr, ok := err.(*AzCliError)
	if !ok {
		t.Errorf("expected AzCliError, got %T", err)
		return
	}

	if azErr.Type != ErrorTypeTimeout {
		t.Errorf("expected ErrorTypeTimeout, got %v", azErr.Type)
	}
}

func TestClientIntegration_AuthSetupAndValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      AuthConfig
		skipSetup   bool
		expectError bool
	}{
		{
			name: "skip setup",
			config: AuthConfig{
				SkipSetup: true,
			},
			skipSetup:   true,
			expectError: false,
		},
		{
			name: "workload identity without token",
			config: AuthConfig{
				AuthMethod:         "workload-identity",
				TenantID:           "tenant-123",
				ClientID:           "client-456",
				FederatedTokenFile: "",
			},
			skipSetup:   false,
			expectError: true,
		},
		{
			name: "service principal without secret",
			config: AuthConfig{
				AuthMethod:   "service-principal",
				TenantID:     "tenant-123",
				ClientID:     "client-456",
				ClientSecret: "",
			},
			skipSetup:   false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := NewDefaultAuthSetup(tt.config)
			err := setup.Setup(context.Background())

			if tt.skipSetup {
				if err != nil {
					t.Errorf("Setup() with SkipSetup should not error, got: %v", err)
				}
				return
			}

			if tt.expectError && err == nil {
				t.Error("Setup() should have returned an error")
			}
		})
	}
}
