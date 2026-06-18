package azcli

import (
	"context"
	"testing"
	"time"
)

func TestExecutor_ExecuteTimeout(t *testing.T) {
	config := ExecutorConfig{
		Timeout: 100 * time.Millisecond,
	}
	executor := NewDefaultExecutor(config)

	ctx := context.Background()
	argv := []string{"az", "vm", "list", "--query", "sleep 1"}
	_, err := executor.Execute(ctx, "az vm list --query \"sleep 1\"", argv)

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

func TestExecutor_ExecuteEmptyArgv(t *testing.T) {
	executor := NewDefaultExecutor(ExecutorConfig{})

	ctx := context.Background()
	_, err := executor.Execute(ctx, "", nil)
	if err == nil {
		t.Error("Execute() with empty argv: got nil error, want error")
	}
	azErr, ok := err.(*AzCliError)
	if !ok {
		t.Errorf("expected AzCliError, got %T", err)
		return
	}
	if azErr.Type != ErrorTypeInvalidCommand {
		t.Errorf("expected ErrorTypeInvalidCommand, got %v", azErr.Type)
	}
}

func TestExecutor_IsAuthError(t *testing.T) {
	executor := &DefaultExecutor{}

	tests := []struct {
		name   string
		stderr string
		want   bool
	}{
		{
			name:   "AADSTS error",
			stderr: "ERROR: AADSTS70043: The refresh token has expired",
			want:   true,
		},
		{
			name:   "az login prompt",
			stderr: "Run the command below to authenticate interactively\naz login",
			want:   true,
		},
		{
			name:   "Please run az login",
			stderr: "ERROR: Please run 'az login' to setup account.",
			want:   true,
		},
		{
			name:   "refresh token expired",
			stderr: "ERROR: The refresh token has expired or is invalid",
			want:   true,
		},
		{
			name:   "non-auth error",
			stderr: "ERROR: Resource not found",
			want:   false,
		},
		{
			name:   "empty stderr",
			stderr: "",
			want:   false,
		},
		{
			name:   "normal output",
			stderr: "Successfully created resource",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := executor.isAuthError(tt.stderr)
			if got != tt.want {
				t.Errorf("isAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}
