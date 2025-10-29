package azcli

import (
	"errors"
	"fmt"
)

type ErrorType string

const (
	ErrorTypeInvalidCommand ErrorType = "invalid_command"
	ErrorTypeCommandDenied  ErrorType = "command_denied"
	ErrorTypeConsentDenied  ErrorType = "consent_denied"
	ErrorTypeExecution      ErrorType = "execution_failed"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeParseOutput    ErrorType = "parse_output"
	ErrorTypeAuth           ErrorType = "auth_failed"
)

var (
	ErrInvalidCommand  = errors.New("invalid command format")
	ErrCommandDenied   = errors.New("command denied by security policy")
	ErrConsentDenied   = errors.New("user consent denied")
	ErrExecutionFailed = errors.New("command execution failed")
	ErrTimeout         = errors.New("command execution timeout")
	ErrParseOutput     = errors.New("failed to parse command output")
	ErrAuthFailed      = errors.New("azure authentication failed")
)

type AzCliError struct {
	Type    ErrorType
	Message string
	Command string
	Context map[string]any
}

func (e *AzCliError) Error() string {
	if e.Command != "" {
		return fmt.Sprintf("[%s] %s (command: %s)", e.Type, e.Message, e.Command)
	}
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

func NewAzCliError(errType ErrorType, message string, command string) *AzCliError {
	return &AzCliError{
		Type:    errType,
		Message: message,
		Command: command,
		Context: make(map[string]any),
	}
}

func (e *AzCliError) WithContext(key string, value any) *AzCliError {
	e.Context[key] = value
	return e
}
