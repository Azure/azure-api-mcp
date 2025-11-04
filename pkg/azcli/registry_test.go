package azcli

import (
	"strings"
	"testing"
)

func TestGenerateToolDescription(t *testing.T) {
	tests := []struct {
		name                string
		readOnlyMode        bool
		defaultSubscription string
		wantContains        []string
		wantNotContains     []string
	}{
		{
			name:                "read-only mode",
			readOnlyMode:        true,
			defaultSubscription: "",
			wantContains: []string{
				"Execute Azure CLI commands",
				"Mode: READ-ONLY",
				"List VMs:",
				"Show storage account",
			},
			wantNotContains: []string{
				"Mode: READ-WRITE",
				"Create resource group:",
				"Create AKS cluster:",
				"Default Subscription:",
			},
		},
		{
			name:                "read-write mode",
			readOnlyMode:        false,
			defaultSubscription: "",
			wantContains: []string{
				"Execute Azure CLI commands",
				"Mode: READ-WRITE",
				"List VMs:",
				"Create resource group:",
				"Create AKS cluster:",
			},
			wantNotContains: []string{
				"Mode: READ-ONLY",
				"Default Subscription:",
			},
		},
		{
			name:                "with default subscription",
			readOnlyMode:        true,
			defaultSubscription: "my-test-subscription",
			wantContains: []string{
				"Execute Azure CLI commands",
				"Mode: READ-ONLY",
				"Default Subscription: my-test-subscription",
			},
			wantNotContains: []string{
				"Mode: READ-WRITE",
			},
		},
		{
			name:                "read-write with subscription",
			readOnlyMode:        false,
			defaultSubscription: "prod-subscription-001",
			wantContains: []string{
				"Execute Azure CLI commands",
				"Mode: READ-WRITE",
				"Default Subscription: prod-subscription-001",
				"Create resource group:",
			},
			wantNotContains: []string{
				"Mode: READ-ONLY",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := generateToolDescription(tt.readOnlyMode, tt.defaultSubscription)

			for _, want := range tt.wantContains {
				if !strings.Contains(desc, want) {
					t.Errorf("generateToolDescription() missing expected substring %q in description:\n%s", want, desc)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(desc, notWant) {
					t.Errorf("generateToolDescription() contains unexpected substring %q in description:\n%s", notWant, desc)
				}
			}
		})
	}
}

func TestGenerateToolDescriptionExamples(t *testing.T) {
	t.Run("contains required examples", func(t *testing.T) {
		desc := generateToolDescription(false, "")

		requiredExamples := []string{
			"List VMs:",
			"Show storage account",
			"List AKS clusters:",
			"Get AKS credentials:",
		}

		for _, example := range requiredExamples {
			if !strings.Contains(desc, example) {
				t.Errorf("generateToolDescription() missing required example: %q", example)
			}
		}
	})

	t.Run("read-write examples only in non-readonly mode", func(t *testing.T) {
		readOnlyDesc := generateToolDescription(true, "")
		readWriteDesc := generateToolDescription(false, "")

		writeExamples := []string{
			"Create resource group:",
			"Create AKS cluster:",
		}

		for _, example := range writeExamples {
			if strings.Contains(readOnlyDesc, example) {
				t.Errorf("generateToolDescription() in read-only mode should not contain write example: %q", example)
			}
			if !strings.Contains(readWriteDesc, example) {
				t.Errorf("generateToolDescription() in read-write mode should contain write example: %q", example)
			}
		}
	})
}
