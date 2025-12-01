package azcli

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type mockValidator struct {
	validateFunc func(cmdStr string) error
}

func (m *mockValidator) Validate(cmdStr string) error {
	if m.validateFunc != nil {
		return m.validateFunc(cmdStr)
	}
	return nil
}

type mockExecutor struct {
	executeFunc func(ctx context.Context, cmdStr string) (*Result, error)
	callCount   int
}

func (m *mockExecutor) Execute(ctx context.Context, cmdStr string) (*Result, error) {
	m.callCount++
	if m.executeFunc != nil {
		return m.executeFunc(ctx, cmdStr)
	}
	return &Result{
		Output:   json.RawMessage(`{"status":"ok"}`),
		ExitCode: 0,
	}, nil
}

type mockAuthSetup struct {
	setupFunc func(ctx context.Context) error
	callCount int
}

func (m *mockAuthSetup) Setup(ctx context.Context) error {
	m.callCount++
	if m.setupFunc != nil {
		return m.setupFunc(ctx)
	}
	return nil
}

func TestClient_ExecuteCommand_Success(t *testing.T) {
	mockExec := &mockExecutor{}
	mockVal := &mockValidator{}

	client := &DefaultClient{
		validator: mockVal,
		executor:  mockExec,
	}

	ctx := context.Background()
	result, err := client.ExecuteCommand(ctx, "az vm list")

	if err != nil {
		t.Errorf("ExecuteCommand() error = %v, want nil", err)
	}
	if result == nil {
		t.Error("ExecuteCommand() result = nil, want non-nil")
	}
	if mockExec.callCount != 1 {
		t.Errorf("executor.Execute() called %d times, want 1", mockExec.callCount)
	}
}

func TestClient_ExecuteCommand_ValidationError(t *testing.T) {
	mockExec := &mockExecutor{}
	mockVal := &mockValidator{
		validateFunc: func(cmdStr string) error {
			return NewAzCliError(ErrorTypeCommandDenied, "command denied", cmdStr)
		},
	}

	client := &DefaultClient{
		validator: mockVal,
		executor:  mockExec,
	}

	ctx := context.Background()
	_, err := client.ExecuteCommand(ctx, "az vm delete --force")

	if err == nil {
		t.Error("ExecuteCommand() error = nil, want error")
	}
	if mockExec.callCount != 0 {
		t.Errorf("executor.Execute() called %d times, want 0", mockExec.callCount)
	}
}

func TestClient_ExecuteCommand_AuthRetry(t *testing.T) {
	firstCall := true
	mockExec := &mockExecutor{
		executeFunc: func(ctx context.Context, cmdStr string) (*Result, error) {
			if firstCall {
				firstCall = false
				return nil, NewAzCliError(ErrorTypeAuth, "authentication expired", cmdStr)
			}
			return &Result{
				Output:   json.RawMessage(`{"status":"ok"}`),
				ExitCode: 0,
				Duration: 100 * time.Millisecond,
			}, nil
		},
	}
	mockVal := &mockValidator{}
	mockAuth := &mockAuthSetup{}

	client := &DefaultClient{
		validator: mockVal,
		executor:  mockExec,
		authSetup: mockAuth,
	}

	ctx := context.Background()
	result, err := client.ExecuteCommand(ctx, "az vm list")

	if err != nil {
		t.Errorf("ExecuteCommand() error = %v, want nil", err)
	}
	if result == nil {
		t.Error("ExecuteCommand() result = nil, want non-nil")
	}
	if mockExec.callCount != 2 {
		t.Errorf("executor.Execute() called %d times, want 2", mockExec.callCount)
	}
	if mockAuth.callCount != 1 {
		t.Errorf("authSetup.Setup() called %d times, want 1", mockAuth.callCount)
	}
}

func TestClient_ExecuteCommand_AuthRetryFailed(t *testing.T) {
	mockExec := &mockExecutor{
		executeFunc: func(ctx context.Context, cmdStr string) (*Result, error) {
			return nil, NewAzCliError(ErrorTypeAuth, "authentication expired", cmdStr)
		},
	}
	mockVal := &mockValidator{}
	mockAuth := &mockAuthSetup{
		setupFunc: func(ctx context.Context) error {
			return errors.New("re-authentication failed")
		},
	}

	client := &DefaultClient{
		validator: mockVal,
		executor:  mockExec,
		authSetup: mockAuth,
	}

	ctx := context.Background()
	_, err := client.ExecuteCommand(ctx, "az vm list")

	if err == nil {
		t.Error("ExecuteCommand() error = nil, want error")
	}
	var azErr *AzCliError
	if !errors.As(err, &azErr) || azErr.Type != ErrorTypeAuth {
		t.Errorf("ExecuteCommand() error type = %T, want AzCliError with ErrorTypeAuth", err)
	}
	if mockExec.callCount != 1 {
		t.Errorf("executor.Execute() called %d times, want 1", mockExec.callCount)
	}
	if mockAuth.callCount != 1 {
		t.Errorf("authSetup.Setup() called %d times, want 1", mockAuth.callCount)
	}
}

func TestClient_ExecuteCommand_NoAuthSetup(t *testing.T) {
	mockExec := &mockExecutor{
		executeFunc: func(ctx context.Context, cmdStr string) (*Result, error) {
			return nil, NewAzCliError(ErrorTypeAuth, "authentication expired", cmdStr)
		},
	}
	mockVal := &mockValidator{}

	client := &DefaultClient{
		validator: mockVal,
		executor:  mockExec,
		authSetup: nil,
	}

	ctx := context.Background()
	_, err := client.ExecuteCommand(ctx, "az vm list")

	if err == nil {
		t.Error("ExecuteCommand() error = nil, want error")
	}
	if mockExec.callCount != 1 {
		t.Errorf("executor.Execute() called %d times, want 1 (no retry without authSetup)", mockExec.callCount)
	}
}

func TestClient_ExecuteCommand_NonAuthError(t *testing.T) {
	mockExec := &mockExecutor{
		executeFunc: func(ctx context.Context, cmdStr string) (*Result, error) {
			return nil, NewAzCliError(ErrorTypeExecution, "resource not found", cmdStr)
		},
	}
	mockVal := &mockValidator{}
	mockAuth := &mockAuthSetup{}

	client := &DefaultClient{
		validator: mockVal,
		executor:  mockExec,
		authSetup: mockAuth,
	}

	ctx := context.Background()
	_, err := client.ExecuteCommand(ctx, "az vm show --name nonexistent")

	if err == nil {
		t.Error("ExecuteCommand() error = nil, want error")
	}
	if mockExec.callCount != 1 {
		t.Errorf("executor.Execute() called %d times, want 1 (no retry for non-auth errors)", mockExec.callCount)
	}
	if mockAuth.callCount != 0 {
		t.Errorf("authSetup.Setup() called %d times, want 0 (should not retry for non-auth errors)", mockAuth.callCount)
	}
}
