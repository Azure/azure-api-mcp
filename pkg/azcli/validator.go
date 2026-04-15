package azcli

import (
	"fmt"
	"net/url"
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

	if err := v.validateFlagSecurity(cmdStr); err != nil {
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

// azureHostPattern matches known Azure hostnames that are safe destinations for tokens.
var azureHostPattern = regexp.MustCompile(`(?i)(^|\.)(azure\.com|azure\.cn|azure\.us|azure\.de|microsoftonline\.com|microsoft\.com|windows\.net|azure-api\.net|azurecr\.io|azurewebsites\.net|azureedge\.net|msecnd\.net|msftauth\.net|msauth\.net|msftidentity\.com|visualstudio\.com|aka\.ms)$`)

// isAzureHost checks whether a URL points to a known Azure/Microsoft host.
func isAzureHost(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	hostname := parsed.Hostname()
	return azureHostPattern.MatchString(hostname)
}

// extractFlagValue extracts the value of a flag from a list of tokens.
// It handles both --flag=value and --flag value forms.
func extractFlagValue(tokens []string, flag string) (string, bool) {
	for i, t := range tokens {
		if t == flag && i+1 < len(tokens) {
			return tokens[i+1], true
		}
		if strings.HasPrefix(t, flag+"=") {
			return strings.TrimPrefix(t, flag+"="), true
		}
	}
	return "", false
}

// validateFlagSecurity checks for dangerous flag combinations that could lead
// to token exfiltration. This always runs, regardless of security policy or
// read-only mode settings.
//
// Specifically, it blocks "az rest" commands where:
//   - --url points to a non-Azure host (token could be sent to an attacker)
//   - --resource is present with a non-Azure --url (explicit token minting for exfil)
func (v *DefaultValidator) validateFlagSecurity(cmdStr string) error {
	tokens := strings.Fields(cmdStr)

	// Only inspect "az rest" commands
	if len(tokens) < 2 || tokens[0] != "az" || tokens[1] != "rest" {
		return nil
	}

	// Check --url / -u flag
	urlVal, hasURL := extractFlagValue(tokens[2:], "--url")
	if !hasURL {
		urlVal, hasURL = extractFlagValue(tokens[2:], "-u")
	}

	if hasURL && !isAzureHost(urlVal) {
		return NewAzCliError(ErrorTypeCommandDenied,
			"az rest --url must point to a known Azure host; non-Azure URLs are blocked to prevent token exfiltration",
			cmdStr)
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
