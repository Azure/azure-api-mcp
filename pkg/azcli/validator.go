package azcli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Validator interface {
	Validate(cmdStr string) error
}

type DefaultValidator struct {
	readOnlyMode         bool
	enableSecurityPolicy bool
	policy               *SecurityPolicy
	readOnlyPatterns     *ReadOnlyPatterns
}

func NewDefaultValidator(cfg ClientConfig) (*DefaultValidator, error) {
	validator := &DefaultValidator{
		readOnlyMode:         cfg.ReadOnlyMode,
		enableSecurityPolicy: cfg.EnableSecurityPolicy,
	}

	if cfg.EnableSecurityPolicy {
		policy, err := LoadSecurityPolicy(cfg.SecurityPolicyFile)
		if err != nil {
			return nil, err
		}
		validator.policy = policy
	}

	if cfg.ReadOnlyMode {
		patterns, err := LoadReadOnlyPatterns(cfg.ReadOnlyPatternsFile)
		if err != nil {
			return nil, err
		}
		validator.readOnlyPatterns = patterns
	}

	return validator, nil
}

func (v *DefaultValidator) Validate(cmdStr string) error {
	if err := v.validateBasicSecurity(cmdStr); err != nil {
		return err
	}

	if v.enableSecurityPolicy {
		if err := v.checkDenyList(cmdStr); err != nil {
			return err
		}
	}

	if v.readOnlyMode {
		if err := v.checkReadOnly(cmdStr); err != nil {
			return err
		}
	}

	return nil
}

func (v *DefaultValidator) validateBasicSecurity(cmdStr string) error {
	if !strings.HasPrefix(cmdStr, "az ") {
		return NewAzCliError(ErrorTypeInvalidCommand, "command must start with 'az '", cmdStr)
	}

	dangerousChars := []string{"|", ">", "<", "&&", "||", ";", "$", "`", "\n"}
	for _, char := range dangerousChars {
		if strings.Contains(cmdStr, char) {
			return NewAzCliError(ErrorTypeInvalidCommand, fmt.Sprintf("command contains forbidden character: %s", char), cmdStr)
		}
	}

	if strings.Contains(cmdStr, "../") || strings.Contains(cmdStr, "..\\") {
		return NewAzCliError(ErrorTypeInvalidCommand, "path traversal detected", cmdStr)
	}

	return nil
}

func (v *DefaultValidator) checkDenyList(cmdStr string) error {
	if v.policy == nil {
		return nil
	}

	for _, denied := range v.policy.Policy.DenyList {
		if strings.HasPrefix(cmdStr, denied) {
			return NewAzCliError(ErrorTypeCommandDenied, fmt.Sprintf("command denied by security policy: %s", denied), cmdStr)
		}
	}
	return nil
}

func (v *DefaultValidator) checkReadOnly(cmdStr string) error {
	if v.readOnlyPatterns == nil {
		return NewAzCliError(ErrorTypeCommandDenied, "read-only patterns not loaded", cmdStr)
	}

	for _, pattern := range v.readOnlyPatterns.Patterns {
		matched, err := regexp.MatchString(pattern, cmdStr)
		if err != nil {
			continue
		}
		if matched {
			return nil
		}
	}
	return NewAzCliError(ErrorTypeCommandDenied, "command not allowed in read-only mode", cmdStr)
}

func LoadSecurityPolicy(filePath string) (*SecurityPolicy, error) {
	var data []byte

	if filePath == "" {
		data = []byte(DefaultSecurityPolicy)
	} else {
		var err error
		// #nosec G304 - This is the intended behavior: load custom policy file from user-specified path
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file: %w", err)
		}
	}

	var policy SecurityPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	return &policy, nil
}

func LoadReadOnlyPatterns(filePath string) (*ReadOnlyPatterns, error) {
	var data []byte

	if filePath == "" {
		data = []byte(DefaultReadOnlyPatterns)
	} else {
		var err error
		// #nosec G304 - This is the intended behavior: load custom patterns file from user-specified path
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read patterns file: %w", err)
		}
	}

	var patterns ReadOnlyPatterns
	if err := yaml.Unmarshal(data, &patterns); err != nil {
		return nil, fmt.Errorf("failed to parse patterns: %w", err)
	}

	return &patterns, nil
}
