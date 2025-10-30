package azcli

import (
	"context"
	"testing"
	"time"
)

func TestExecutor_ParseCommandString(t *testing.T) {
	executor := &DefaultExecutor{}

	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "simple command",
			input:    "az vm list",
			expected: []string{"az", "vm", "list"},
			wantErr:  false,
		},
		{
			name:     "command with flags",
			input:    "az vm list --resource-group myRG --output json",
			expected: []string{"az", "vm", "list", "--resource-group", "myRG", "--output", "json"},
			wantErr:  false,
		},
		{
			name:     "command with quoted argument",
			input:    `az vm create --name "my vm" --resource-group myRG`,
			expected: []string{"az", "vm", "create", "--name", "my vm", "--resource-group", "myRG"},
			wantErr:  false,
		},
		{
			name:     "command with single quotes",
			input:    "az vm create --name 'my vm' --resource-group myRG",
			expected: []string{"az", "vm", "create", "--name", "my vm", "--resource-group", "myRG"},
			wantErr:  false,
		},
		{
			name:     "command with extra spaces",
			input:    "az  vm   list  --resource-group  myRG",
			expected: []string{"az", "vm", "list", "--resource-group", "myRG"},
			wantErr:  false,
		},
		{
			name:     "empty command",
			input:    "",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "unclosed quote",
			input:    `az vm list --name "unclosed`,
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := executor.parseCommandString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCommandString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(result) != len(tt.expected) {
					t.Errorf("parseCommandString() got %d args, want %d", len(result), len(tt.expected))
					return
				}
				for i := range result {
					if result[i] != tt.expected[i] {
						t.Errorf("parseCommandString() arg[%d] = %v, want %v", i, result[i], tt.expected[i])
					}
				}
			}
		})
	}
}

func TestExecutor_ExecuteTimeout(t *testing.T) {
	config := ExecutorConfig{
		Timeout: 100 * time.Millisecond,
	}
	executor := NewDefaultExecutor(config)

	ctx := context.Background()
	_, err := executor.Execute(ctx, "az vm list --query \"sleep 1\"")

	if err == nil {
		t.Skip("Test skipped: command completed before timeout (az not installed or command too fast)")
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

func TestExecutor_ExecuteInvalidCommand(t *testing.T) {
	executor := NewDefaultExecutor(ExecutorConfig{})

	tests := []struct {
		name    string
		cmdStr  string
		wantErr bool
	}{
		{
			name:    "empty command",
			cmdStr:  "",
			wantErr: true,
		},
		{
			name:    "unclosed quote",
			cmdStr:  `az vm list --name "unclosed`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := executor.Execute(ctx, tt.cmdStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
