package azcli

import (
	"testing"
)

func TestLoadReadOnlyPatternsWithEmptyPath(t *testing.T) {
	patterns, err := LoadReadOnlyPatterns("")
	if err != nil {
		t.Errorf("LoadReadOnlyPatterns(\"\") should not error, got: %v", err)
	}
	if patterns == nil {
		t.Fatal("LoadReadOnlyPatterns(\"\") should return default patterns")
	}
	if len(patterns.Patterns) == 0 {
		t.Error("Default patterns should not be empty")
	}
}

func TestLoadReadOnlyPatternsWithNonExistentPath(t *testing.T) {
	patterns, err := LoadReadOnlyPatterns("/tmp/nonexistent-file-12345.yaml")
	if err == nil {
		t.Error("LoadReadOnlyPatterns with non-existent file should return error")
	}
	if patterns != nil {
		t.Error("LoadReadOnlyPatterns should return nil when file doesn't exist")
	}
}

func TestLoadSecurityPolicyWithEmptyPath(t *testing.T) {
	policy, err := LoadSecurityPolicy("")
	if err != nil {
		t.Errorf("LoadSecurityPolicy(\"\") should not error, got: %v", err)
	}
	if policy == nil {
		t.Fatal("LoadSecurityPolicy(\"\") should return default policy")
	}
	if len(policy.Policy.DenyList) == 0 {
		t.Error("Default policy should not be empty")
	}
}

func TestLoadSecurityPolicyWithNonExistentPath(t *testing.T) {
	policy, err := LoadSecurityPolicy("/tmp/nonexistent-file-12345.yaml")
	if err == nil {
		t.Error("LoadSecurityPolicy with non-existent file should return error")
	}
	if policy != nil {
		t.Error("LoadSecurityPolicy should return nil when file doesn't exist")
	}
}
