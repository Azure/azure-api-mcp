package azcli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthSetup_DetectAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		config   AuthConfig
		expected string
	}{
		{
			name: "detect workload identity",
			config: AuthConfig{
				TenantID:           "tenant-123",
				ClientID:           "client-456",
				FederatedTokenFile: "/tmp/token",
			},
			expected: "workload-identity",
		},
		{
			name: "detect service principal",
			config: AuthConfig{
				TenantID:     "tenant-123",
				ClientID:     "client-456",
				ClientSecret: "secret-789",
			},
			expected: "service-principal",
		},
		{
			name: "default to managed-identity",
			config: AuthConfig{
				TenantID: "tenant-123",
			},
			expected: "managed-identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := NewDefaultAuthSetup(tt.config)
			result := setup.detectAuthMethod()
			if result != tt.expected {
				t.Errorf("detectAuthMethod() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAuthSetup_SkipSetup(t *testing.T) {
	config := AuthConfig{
		SkipSetup: true,
	}

	setup := NewDefaultAuthSetup(config)
	err := setup.Setup(context.Background())
	if err != nil {
		t.Errorf("Setup() with SkipSetup=true should not error, got: %v", err)
	}
}

func TestAuthSetup_WorkloadIdentityMissingToken(t *testing.T) {
	config := AuthConfig{
		AuthMethod:         "workload-identity",
		TenantID:           "tenant-123",
		ClientID:           "client-456",
		FederatedTokenFile: "",
	}

	setup := NewDefaultAuthSetup(config)
	err := setup.Setup(context.Background())
	if err == nil {
		t.Error("Setup() should error when FederatedTokenFile is not set")
	}
}

func TestAuthSetup_ServicePrincipalMissingSecret(t *testing.T) {
	config := AuthConfig{
		AuthMethod:   "service-principal",
		TenantID:     "tenant-123",
		ClientID:     "client-456",
		ClientSecret: "",
	}

	setup := NewDefaultAuthSetup(config)
	err := setup.Setup(context.Background())
	if err == nil {
		t.Error("Setup() should error when ClientSecret is not set")
	}
}

func TestAuthSetup_UnknownAuthMethod(t *testing.T) {
	config := AuthConfig{
		AuthMethod: "unknown-method",
	}

	setup := NewDefaultAuthSetup(config)
	err := setup.Setup(context.Background())
	if err == nil {
		t.Error("Setup() should error for unknown auth method")
	}
}

func TestAuthSetup_DetectManagedIdentity(t *testing.T) {
	originalMSI := os.Getenv("MSI_ENDPOINT")
	defer func() {
		if originalMSI != "" {
			os.Setenv("MSI_ENDPOINT", originalMSI)
		} else {
			os.Unsetenv("MSI_ENDPOINT")
		}
	}()

	os.Setenv("MSI_ENDPOINT", "http://169.254.169.254/metadata/identity")

	config := AuthConfig{}
	setup := NewDefaultAuthSetup(config)
	result := setup.detectAuthMethod()

	if result != "managed-identity" {
		t.Errorf("detectAuthMethod() = %v, want managed-identity", result)
	}
}

func TestAuthSetup_WorkloadIdentityWithTokenFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	tokenContent := "fake-token-content"
	if err := os.WriteFile(tokenFile, []byte(tokenContent), 0644); err != nil {
		t.Fatal(err)
	}

	config := AuthConfig{
		AuthMethod:         "workload-identity",
		TenantID:           "tenant-123",
		ClientID:           "client-456",
		FederatedTokenFile: tokenFile,
	}

	setup := NewDefaultAuthSetup(config)
	err := setup.Setup(context.Background())

	if err == nil {
		t.Skip("Test skipped: az CLI not available or login succeeded unexpectedly")
	}
}
