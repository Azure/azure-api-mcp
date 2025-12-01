package azcli

import (
	"context"
	"errors"
	"log"
)

type Client interface {
	ExecuteCommand(ctx context.Context, cmdStr string) (*Result, error)
	ValidateCommand(cmdStr string) error
}

type DefaultClient struct {
	validator Validator
	executor  Executor
	authSetup AuthSetup
}

func NewClient(cfg ClientConfig) (Client, error) {
	validator, err := NewDefaultValidator(cfg)
	if err != nil {
		return nil, err
	}

	executorConfig := ExecutorConfig{
		Timeout:    cfg.Timeout,
		WorkingDir: cfg.WorkingDir,
	}
	executor := NewDefaultExecutor(executorConfig)

	return &DefaultClient{
		validator: validator,
		executor:  executor,
		authSetup: cfg.AuthSetup,
	}, nil
}

func (c *DefaultClient) ExecuteCommand(ctx context.Context, cmdStr string) (*Result, error) {
	if err := c.validator.Validate(cmdStr); err != nil {
		return nil, err
	}

	result, err := c.executor.Execute(ctx, cmdStr)
	if err != nil {
		var azErr *AzCliError
		if errors.As(err, &azErr) && azErr.Type == ErrorTypeAuth && c.authSetup != nil {
			// Authentication retry logic:
			// When Azure CLI tokens expire (e.g., after long-running server sessions),
			// we detect auth errors from stderr and automatically re-authenticate using
			// the configured auth method (workload identity, managed identity, or service principal).
			// We only retry once to avoid infinite loops. If re-authentication fails, we return
			// the original auth error to the caller.
			log.Printf("[INFO] Authentication error detected, attempting to re-authenticate")
			if authErr := c.authSetup.Setup(ctx); authErr != nil {
				log.Printf("[ERROR] Re-authentication failed: %v", authErr)
				return nil, err
			}
			log.Printf("[INFO] Re-authentication successful, retrying command")
			return c.executor.Execute(ctx, cmdStr)
		}
		return nil, err
	}

	return result, nil
}

func (c *DefaultClient) ValidateCommand(cmdStr string) error {
	return c.validator.Validate(cmdStr)
}
