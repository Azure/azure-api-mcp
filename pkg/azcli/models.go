package azcli

import (
	"encoding/json"
	"time"
)

type Result struct {
	Output   json.RawMessage
	ExitCode int
	Error    string
	Duration time.Duration
}

type AuthConfig struct {
	SkipSetup           bool
	AuthMethod          string
	TenantID            string
	ClientID            string
	FederatedTokenFile  string
	ClientSecret        string
	DefaultSubscription string
}

type ExecutorConfig struct {
	Timeout        time.Duration
	WorkingDir     string
	MaxOutputSize  int64
	AllowedEnvVars []string
}

type ClientConfig struct {
	ReadOnlyMode         bool
	EnableSecurityPolicy bool
	Timeout              time.Duration
	WorkingDir           string
	SecurityPolicyFile   string
	ReadOnlyPatternsFile string
}

type SecurityPolicy struct {
	Version string      `yaml:"version"`
	Policy  PolicyRules `yaml:"policy"`
}

type PolicyRules struct {
	DenyList []string `yaml:"denyList"`
}

type ReadOnlyPatterns struct {
	Patterns []string `yaml:"patterns"`
}
