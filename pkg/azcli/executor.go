package azcli

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/Azure/azure-api-mcp/internal/logger"
)

type Executor interface {
	Execute(ctx context.Context, cmdStr string, argv []string) (*Result, error)
}

type DefaultExecutor struct {
	config ExecutorConfig
}

func NewDefaultExecutor(config ExecutorConfig) *DefaultExecutor {
	if config.Timeout == 0 {
		config.Timeout = 120 * time.Second
	}
	if config.MaxOutputSize == 0 {
		config.MaxOutputSize = 10 * 1024 * 1024
	}
	return &DefaultExecutor{
		config: config,
	}
}

// Execute runs the previously-tokenized argv. The caller (Client) is
// responsible for producing argv via tokenizeCommand so the validator and
// executor see byte-identical argv.
func (e *DefaultExecutor) Execute(ctx context.Context, cmdStr string, argv []string) (*Result, error) {
	startTime := time.Now()

	if len(argv) == 0 {
		return nil, NewAzCliError(ErrorTypeInvalidCommand, "empty argv", cmdStr)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	// #nosec G204 - This is the intended behavior: execute validated Azure CLI commands
	cmd := exec.CommandContext(ctxWithTimeout, argv[0], argv[1:]...)

	if e.config.WorkingDir != "" {
		cmd.Dir = e.config.WorkingDir
	}

	if len(e.config.AllowedEnvVars) > 0 {
		cmd.Env = e.config.AllowedEnvVars
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(startTime)

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if ctxWithTimeout.Err() == context.DeadlineExceeded {
			return nil, NewAzCliError(ErrorTypeTimeout, "command execution timed out", cmdStr).
				WithContext("timeout", e.config.Timeout)
		} else {
			return nil, NewAzCliError(ErrorTypeExecution, err.Error(), cmdStr)
		}
	}

	outputBytes := stdout.Bytes()
	if int64(len(outputBytes)) > e.config.MaxOutputSize {
		return nil, NewAzCliError(ErrorTypeExecution, "output size exceeds limit", cmdStr).
			WithContext("size", len(outputBytes)).
			WithContext("limit", e.config.MaxOutputSize)
	}

	output := json.RawMessage(outputBytes)
	if len(outputBytes) == 0 {
		output = json.RawMessage("null")
	}

	errorMsg := ""
	if stderr.Len() > 0 {
		errorMsg = stderr.String()
		if e.isAuthError(errorMsg) {
			logger.Warn("Authentication error detected in command output")
			return nil, NewAzCliError(ErrorTypeAuth, "authentication expired or invalid", cmdStr).
				WithContext("stderr", errorMsg)
		}
	}

	result := &Result{
		Output:   output,
		ExitCode: exitCode,
		Error:    errorMsg,
		Duration: duration,
	}

	return result, nil
}

// isAuthError detects authentication-related errors from Azure CLI stderr output.
// This method checks for common authentication failure patterns based on actual Azure CLI error messages.
//
// Detected error patterns:
//  1. AADSTS errors: Azure Active Directory STS (Security Token Service) error codes
//     Example: "ERROR: AADSTS70043: The refresh token has expired or is invalid"
//     Common codes: AADSTS70043 (BadTokenDueToSignInFrequency), AADSTS70008 (ExpiredOrRevokedGrant)
//  2. Token expiration: Messages indicating expired or invalid refresh tokens
//     Example: "The refresh token has expired or is invalid due to sign-in frequency checks"
//  3. Login prompts: Azure CLI prompting for manual authentication
//     Example: "Run the command below to authenticate interactively: az login"
//     Example: "ERROR: Please run 'az login' to setup account."
//
// Note: This detection is based on observed Azure CLI error message patterns (as of Azure CLI 2.x).
// While these patterns cover the most common authentication failures, Azure CLI may introduce
// new error message formats in future versions. The patterns are conservative to minimize
// false positives (incorrectly detecting non-auth errors as auth errors).
//
// References:
//   - AADSTS error codes: https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
//   - Azure CLI authentication: https://learn.microsoft.com/cli/azure/authenticate-azure-cli-interactively
//   - Tested against Azure CLI 2.x error outputs for token expiration scenarios
func (e *DefaultExecutor) isAuthError(stderr string) bool {
	if strings.Contains(stderr, "ERROR: AADSTS") {
		return true
	}
	if strings.Contains(stderr, "az login") && strings.Contains(stderr, "authenticate") {
		return true
	}
	if strings.Contains(stderr, "Please run 'az login'") {
		return true
	}
	if strings.Contains(stderr, "refresh token has expired") {
		return true
	}
	return false
}
