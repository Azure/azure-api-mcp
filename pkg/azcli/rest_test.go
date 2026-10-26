package azcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClient_RESTCannotBeEnabled(t *testing.T) {
	dir := t.TempDir()
	emptyPolicy := filepath.Join(dir, "policy.yaml")
	allowREST := filepath.Join(dir, "readonly.yaml")
	for path, contents := range map[string]string{
		emptyPolicy: "version: \"1.0\"\npolicy:\n  denyList: []\n",
		allowREST:   "patterns:\n  - '^az rest'\n  - '.*'\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	commands := []string{
		"az rest",
		"az rest --help",
		"az rest --method get",
		"az rest --url https://management.azure.com/subscriptions --resource https://management.azure.com/",
		"az rest --url https://evil.example/ --resource https://management.azure.com/",
		"az rest --url https://127.0.0.1/",
		"az rest --url https://graph.microsoft.com/v1.0/me",
		"az rest --url https://account.blob.core.windows.net/container",
		"az rest --url /subscriptions",
		"az rest --resource https://management.azure.com/",
		"az rest -u https://management.azure.com/",
		"az rest --uri https://management.azure.com/",
		"az rest --uri=https://management.azure.com/",
		"az rest --url=https://management.azure.com/",
		"az rest --url=https://management.azure.com/ --url=https://evil.example/",
		`az rest --u"rl"=https://management.azure.com/`,
		`az "rest" --url https://management.azure.com/`,
		`az 'rest'`,
		`"a"z re"st"`,
		`az re''st`,
		"az REST",
		"az ReSt",
		"  az   rest  ",
		"az --debug rest",
		"az --verbose --only-show-errors rest",
		"az --output json rest",
		"az --output=json rest",
		"az -ojson rest",
		"az -o json rest",
		"az --subscription test rest",
		"az -stest rest",
		"az --query rest rest",
		`az --query="rest" re"st"`,
		"az --debug --output=json --query rest rest",
	}
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} {
		commands = append(commands, "az rest --method "+method+" --url https://management.azure.com/")
	}

	for _, readOnly := range []bool{false, true} {
		for _, policyEnabled := range []bool{false, true} {
			for _, custom := range []bool{false, true} {
				t.Run(fmt.Sprintf("readonly=%t/policy=%t/custom=%t", readOnly, policyEnabled, custom), func(t *testing.T) {
					cfg := ClientConfig{ReadOnlyMode: readOnly, EnableSecurityPolicy: policyEnabled}
					if custom {
						cfg.SecurityPolicyFile = emptyPolicy
						cfg.ReadOnlyPatternsFile = allowREST
					}
					client, err := NewClient(cfg)
					if err != nil {
						t.Fatal(err)
					}
					executor := &mockExecutor{}
					auth := &mockAuthSetup{}
					client.(*DefaultClient).executor = executor
					client.(*DefaultClient).authSetup = auth
					for _, command := range commands {
						t.Run(command, func(t *testing.T) {
							assertRESTDenied(t, client.ValidateCommand(command))
							result, err := client.ExecuteCommand(context.Background(), command)
							assertRESTDenied(t, err)
							if result != nil {
								t.Fatal("denied command returned a result")
							}
						})
					}
					if executor.callCount != 0 || auth.callCount != 0 {
						t.Fatalf("REST reached executor (%d calls) or authentication (%d calls)", executor.callCount, auth.callCount)
					}
				})
			}
		}
	}
}

func assertRESTDenied(t *testing.T, err error) {
	t.Helper()
	var cliErr *AzCliError
	if !errors.As(err, &cliErr) || cliErr.Type != ErrorTypeCommandDenied ||
		!strings.Contains(cliErr.Message, "az rest is permanently disabled and cannot be enabled by policy") {
		t.Fatalf("expected permanent REST denial, got %v", err)
	}
}

func TestClient_RESTGuardPreservesOtherCommands(t *testing.T) {
	client, err := NewClient(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"az aks show --name rest --resource-group rg",
		"az vm list --resource-group rest",
		"az monitor metrics list --resource rest",
		"az group show --name rest",
		"az resource show --ids rest",
		"az backup restore restore-disks --help",
		"az --query rest aks list",
		"az --query=rest aks list",
		"az --subscription rest aks list",
		"az -srest aks list",
		"az --debug --output json aks list",
		"az --help",
		"az --version",
	} {
		t.Run(command, func(t *testing.T) {
			if err := client.ValidateCommand(command); err != nil {
				t.Fatalf("non-REST command rejected: %v", err)
			}
		})
	}
}

func TestClient_RESTGuardRejectsAmbiguousCommands(t *testing.T) {
	client, err := NewClient(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`az "rest`,
		"az --unknown rest",
		"az --out json rest",
		"az --deb rest",
		"az -- rest",
		"az --debug=true rest",
		"az --output",
		"az --query --debug rest",
	} {
		t.Run(command, func(t *testing.T) {
			if err := client.ValidateCommand(command); err == nil {
				t.Fatal("ambiguous command was accepted")
			}
		})
	}
}
