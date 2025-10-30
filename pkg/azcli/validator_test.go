package azcli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidator_ValidateBasicSecurity(t *testing.T) {
	validator := &DefaultValidator{
		readOnlyMode:         false,
		enableSecurityPolicy: false,
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid az command",
			input:   "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "command without az prefix",
			input:   "ls -la",
			wantErr: true,
		},
		{
			name:    "command with pipe",
			input:   "az vm list | cat /etc/passwd",
			wantErr: true,
		},
		{
			name:    "command with redirect",
			input:   "az vm list > output.txt",
			wantErr: true,
		},
		{
			name:    "command with semicolon",
			input:   "az vm list; rm -rf /",
			wantErr: true,
		},
		{
			name:    "command with dollar sign",
			input:   "az vm list $VAR",
			wantErr: true,
		},
		{
			name:    "command with backtick",
			input:   "az vm list `whoami`",
			wantErr: true,
		},
		{
			name:    "command with path traversal",
			input:   "az vm list --file ../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "command with newline",
			input:   "az vm list\nrm -rf /",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateBasicSecurity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBasicSecurity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidator_CheckReadOnly(t *testing.T) {
	tmpDir := t.TempDir()
	patternsFile := filepath.Join(tmpDir, "readonly-patterns.yaml")

	patternsContent := `patterns:
  - "^az [a-z-]+ list($| )"
  - "^az [a-z-]+ show($| )"
  - "^az account show($| )"
`
	if err := os.WriteFile(patternsFile, []byte(patternsContent), 0644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadReadOnlyPatterns(patternsFile)
	if err != nil {
		t.Fatal(err)
	}

	validator := &DefaultValidator{
		readOnlyMode:     true,
		readOnlyPatterns: patterns,
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "read-only list command",
			input:   "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only show command",
			input:   "az vm show --name myVM --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only account show",
			input:   "az account show",
			wantErr: false,
		},
		{
			name:    "write command - create",
			input:   "az vm create --name myVM --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - delete",
			input:   "az vm delete --name myVM --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - update",
			input:   "az vm update --name myVM --resource-group myRG",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.checkReadOnly(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkReadOnly() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidator_CheckDenyList(t *testing.T) {
	policy := &SecurityPolicy{
		Version: "1.0",
		Policy: PolicyRules{
			DenyList: []string{
				"az account clear",
				"az login",
				"az logout",
				"az vm delete",
				"az group delete",
			},
		},
	}

	validator := &DefaultValidator{
		enableSecurityPolicy: true,
		policy:               policy,
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "allowed command",
			input:   "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "denied - account clear",
			input:   "az account clear",
			wantErr: true,
		},
		{
			name:    "denied - login",
			input:   "az login",
			wantErr: true,
		},
		{
			name:    "denied - vm delete",
			input:   "az vm delete --name myVM",
			wantErr: true,
		},
		{
			name:    "denied - group delete",
			input:   "az group delete --name myRG",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.checkDenyList(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkDenyList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadReadOnlyPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	patternsFile := filepath.Join(tmpDir, "patterns.yaml")

	content := `patterns:
  - "^az [a-z-]+ list($| )"
  - "^az [a-z-]+ show($| )"
`
	if err := os.WriteFile(patternsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadReadOnlyPatterns(patternsFile)
	if err != nil {
		t.Errorf("LoadReadOnlyPatterns() error = %v", err)
	}

	if len(patterns.Patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(patterns.Patterns))
	}
}

func TestLoadSecurityPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	content := `version: "1.0"
policy:
  denyList:
    - "az account clear"
    - "az login"
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	policy, err := LoadSecurityPolicy(policyFile)
	if err != nil {
		t.Errorf("LoadSecurityPolicy() error = %v", err)
	}

	if policy.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", policy.Version)
	}

	if len(policy.Policy.DenyList) != 2 {
		t.Errorf("expected 2 denied commands, got %d", len(policy.Policy.DenyList))
	}
}
