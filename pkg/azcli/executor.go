package azcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Executor interface {
	Execute(ctx context.Context, cmdStr string) (*Result, error)
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

func (e *DefaultExecutor) Execute(ctx context.Context, cmdStr string) (*Result, error) {
	startTime := time.Now()

	args, err := e.parseCommandString(cmdStr)
	if err != nil {
		return nil, NewAzCliError(ErrorTypeInvalidCommand, err.Error(), cmdStr)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctxWithTimeout, args[0], args[1:]...)

	if e.config.WorkingDir != "" {
		cmd.Dir = e.config.WorkingDir
	}

	if len(e.config.AllowedEnvVars) > 0 {
		cmd.Env = e.config.AllowedEnvVars
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
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
	}

	result := &Result{
		Output:   output,
		ExitCode: exitCode,
		Error:    errorMsg,
		Duration: duration,
	}

	return result, nil
}

func (e *DefaultExecutor) parseCommandString(cmdStr string) ([]string, error) {
	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return nil, fmt.Errorf("empty command string")
	}

	args := []string{}
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for i, ch := range cmdStr {
		switch {
		case ch == '"' || ch == '\'':
			if !inQuote {
				inQuote = true
				quoteChar = ch
			} else if ch == quoteChar {
				inQuote = false
				quoteChar = 0
			} else {
				current.WriteRune(ch)
			}
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		case ch == '\\' && i+1 < len(cmdStr):
			next := rune(cmdStr[i+1])
			if next == '"' || next == '\'' || next == '\\' {
				current.WriteRune(next)
				i++
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}

	if inQuote {
		return nil, fmt.Errorf("unclosed quote in command string")
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("no command found")
	}

	return args, nil
}
