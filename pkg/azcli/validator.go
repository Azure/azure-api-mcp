package azcli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Validator inspects a command before execution. The caller is responsible for
// producing argv via tokenizeCommand and passing both the raw cmdStr (for
// error-message context) and the canonical argv (for all token-level
// decisions). Keeping both layers on the same argv eliminates the entire class
// of tokenizer-divergence bypasses where a quoted payload looks one way to the
// guard and another way to the executor.
type Validator interface {
	Validate(cmdStr string, argv []string) error
}

type DefaultValidator struct {
	readOnlyMode         bool
	enableSecurityPolicy bool
	policy               *SecurityPolicy
	readOnlyPatterns     *ReadOnlyPatterns

	// policyDenyArgv is the deny list pre-tokenized once at load time so
	// checkDenyList can match by structural argv-prefix instead of raw-string
	// HasPrefix. Empty when enableSecurityPolicy is false.
	policyDenyArgv [][]string

	// credentialDenyArgv is the hardcoded credential-bearing command deny
	// list, pre-tokenized for structural argv-prefix matching.
	credentialDenyArgv [][]string
}

// credentialDenyPrefixes lists commands that return reusable credentials.
// These match the broad read-only regexes (list / show / get-*) but are never
// allowed in read-only mode regardless of pattern matches.
var credentialDenyPrefixes = []string{
	"az account get-access-token",
	"az aks get-credentials",
	"az fleet get-credentials",
	"az ad app credential",
	"az ad sp credential",
	"az storage account keys list",
	"az storage account show-connection-string",
	"az keyvault secret show",
	"az keyvault secret list",
	"az keyvault secret download",
	"az cosmosdb keys list",
	"az cosmosdb list-connection-strings",
	"az redis list-keys",
	"az acr credential show",
	"az cognitiveservices account keys list",
	"az servicebus namespace authorization-rule keys list",
	"az eventhubs namespace authorization-rule keys list",
	"az webapp config appsettings list",
	"az functionapp config appsettings list",
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
		validator.policyDenyArgv = tokenizePolicyEntries(policy.Policy.DenyList)
	}

	if cfg.ReadOnlyMode {
		patterns, err := LoadReadOnlyPatterns(cfg.ReadOnlyPatternsFile)
		if err != nil {
			return nil, err
		}
		validator.readOnlyPatterns = patterns
	}

	validator.credentialDenyArgv = tokenizePolicyEntries(credentialDenyPrefixes)

	return validator, nil
}

// tokenizePolicyEntries pre-tokenizes every deny-list string once so request-
// time matching is pure structural slice-prefix comparison and cannot be
// evaded by quoting. Entries that fail to tokenize (malformed) are skipped
// because they could never match a real argv.
func tokenizePolicyEntries(entries []string) [][]string {
	out := make([][]string, 0, len(entries))
	for _, e := range entries {
		toks, err := tokenizeCommand(e)
		if err != nil || len(toks) == 0 {
			continue
		}
		out = append(out, toks)
	}
	return out
}

func (v *DefaultValidator) Validate(cmdStr string, argv []string) error {
	if err := v.validateBasicSecurity(cmdStr, argv); err != nil {
		return err
	}

	if err := v.validateCommandAvailability(cmdStr, argv); err != nil {
		return err
	}

	if v.enableSecurityPolicy {
		if err := v.checkDenyList(cmdStr, argv); err != nil {
			return err
		}
	}

	if v.readOnlyMode {
		if err := v.checkReadOnly(cmdStr, argv); err != nil {
			return err
		}
	}

	return nil
}

// validateBasicSecurity enforces the always-on guards.
//
// The first two checks (dangerous characters and path traversal) intentionally
// run on the raw cmdStr because they are literal byte-pattern guards whose
// meaning is independent of tokenization — a shell metacharacter is dangerous
// whether it is quoted or not, and we want the human-approved cli_command
// text to be obviously shell-safe.
//
// The remaining checks run on argv so a quoted payload cannot hide a
// dangerous shape from the guard while still reaching the executor unchanged.
func (v *DefaultValidator) validateBasicSecurity(cmdStr string, argv []string) error {
	dangerousChars := []string{"|", ">", "<", "&&", "||", ";", "$", "`", "\n"}
	for _, char := range dangerousChars {
		if strings.Contains(cmdStr, char) {
			return NewAzCliError(ErrorTypeInvalidCommand, fmt.Sprintf("command contains forbidden character: %s", char), cmdStr)
		}
	}

	if strings.Contains(cmdStr, "../") || strings.Contains(cmdStr, "..\\") {
		return NewAzCliError(ErrorTypeInvalidCommand, "path traversal detected", cmdStr)
	}

	if len(argv) == 0 || argv[0] != "az" {
		return NewAzCliError(ErrorTypeInvalidCommand, "command must start with 'az '", cmdStr)
	}

	// Azure CLI treats an argument value starting with "@" as a file-load
	// directive (e.g. --query @file, --body @file, --parameters=@file.json).
	// Reject tokens whose value position begins with "@" while still allowing
	// "@" inside values (e.g. UPNs like alice@contoso.com). Running on argv
	// (not strings.Fields(cmdStr)) means a quoted "@/etc/passwd" still trips.
	for _, tok := range argv {
		if strings.HasPrefix(tok, "@") {
			return NewAzCliError(ErrorTypeInvalidCommand, "command contains forbidden file-load token starting with '@'", cmdStr)
		}
		if strings.HasPrefix(tok, "-") && strings.Contains(tok, "=@") {
			return NewAzCliError(ErrorTypeInvalidCommand, "command contains forbidden file-load token '=@'", cmdStr)
		}
	}

	return nil
}

// validateCommandAvailability rejects commands that cannot be enabled by policy.
// Inspect the same argv as the executor, including Azure CLI's case-insensitive
// command names and global options placed before the command. Stop at the first
// command token so a resource name or query value of "rest" is not rejected.
func (v *DefaultValidator) validateCommandAvailability(cmdStr string, argv []string) error {
	for i := 1; i < len(argv); i++ {
		token := argv[i]
		if !strings.HasPrefix(token, "-") {
			if strings.EqualFold(token, "rest") {
				return NewAzCliError(ErrorTypeCommandDenied,
					"az rest is permanently disabled and cannot be enabled by policy", cmdStr)
			}
			return nil
		}

		flag, _, hasValue := strings.Cut(token, "=")
		switch flag {
		case "--debug", "--verbose", "--only-show-errors", "--help", "-h", "--version":
			if hasValue {
				return NewAzCliError(ErrorTypeInvalidCommand, "unexpected value for global flag", cmdStr)
			}
		case "--output", "-o", "--query", "--subscription", "-s":
			if !hasValue {
				i++
				if i >= len(argv) || strings.HasPrefix(argv[i], "-") {
					return NewAzCliError(ErrorTypeInvalidCommand, "missing value for global option", cmdStr)
				}
			}
		default:
			// Azure CLI accepts attached values for short options, such as
			// -ojson. Unknown or abbreviated leading options are ambiguous:
			// require them after the command instead of guessing their arity.
			if (strings.HasPrefix(token, "-o") || strings.HasPrefix(token, "-s")) && len(token) > 2 {
				continue
			}
			return NewAzCliError(ErrorTypeInvalidCommand,
				"unrecognized leading option; place the Azure CLI command before its options", cmdStr)
		}
	}
	return nil
}

// hasArgvPrefix reports whether argv starts with the prefix tokens. Pure
// structural comparison — quoting in the original cmdStr cannot change the
// outcome because both sides have already been canonicalized through the
// shared lexer.
func hasArgvPrefix(argv, prefix []string) bool {
	if len(argv) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if argv[i] != p {
			return false
		}
	}
	return true
}

func (v *DefaultValidator) checkDenyList(cmdStr string, argv []string) error {
	if v.policy == nil {
		return nil
	}

	for i, denied := range v.policyDenyArgv {
		if hasArgvPrefix(argv, denied) {
			// Echo the operator-facing form of the deny rule (the original
			// string from the loaded policy), not the tokenized form.
			return NewAzCliError(ErrorTypeCommandDenied,
				fmt.Sprintf("command denied by security policy: %s", v.policy.Policy.DenyList[i]),
				cmdStr)
		}
	}
	return nil
}

func (v *DefaultValidator) checkReadOnly(cmdStr string, argv []string) error {
	if v.readOnlyPatterns == nil {
		return NewAzCliError(ErrorTypeCommandDenied, "read-only patterns not loaded", cmdStr)
	}

	// Hardcoded denylist: credential-bearing commands are never allowed in
	// readonly mode, regardless of pattern matches. Matched structurally on
	// argv so quoting cannot bypass.
	for _, denied := range v.credentialDenyArgv {
		if hasArgvPrefix(argv, denied) {
			return NewAzCliError(ErrorTypeCommandDenied,
				"command returns credential material and is not allowed in read-only mode", cmdStr)
		}
	}

	// Regex allowlist: run patterns against the canonical, quote-stripped form
	// of the command (argv joined with single spaces). This way
	//   az vm "list"
	// matches the same pattern as
	//   az vm list
	// and `^az ` anchors behave consistently regardless of input quoting.
	canonical := strings.Join(argv, " ")
	for _, pattern := range v.readOnlyPatterns.Patterns {
		matched, err := regexp.MatchString(pattern, canonical)
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
