package azcli

import (
	"context"
)

type Client interface {
	ExecuteCommand(ctx context.Context, cmdStr string) (*Result, error)
	ValidateCommand(cmdStr string) error
}

type DefaultClient struct {
	validator Validator
	executor  Executor
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
	}, nil
}

func (c *DefaultClient) ExecuteCommand(ctx context.Context, cmdStr string) (*Result, error) {
	if err := c.validator.Validate(cmdStr); err != nil {
		return nil, err
	}

	return c.executor.Execute(ctx, cmdStr)
}

func (c *DefaultClient) ValidateCommand(cmdStr string) error {
	return c.validator.Validate(cmdStr)
}
