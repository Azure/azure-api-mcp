package azcli

import "testing"

func TestTokenizeCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "simple command",
			input:    "az vm list",
			expected: []string{"az", "vm", "list"},
			wantErr:  false,
		},
		{
			name:     "command with flags",
			input:    "az vm list --resource-group myRG --output json",
			expected: []string{"az", "vm", "list", "--resource-group", "myRG", "--output", "json"},
			wantErr:  false,
		},
		{
			name:     "command with quoted argument",
			input:    `az vm create --name "my vm" --resource-group myRG`,
			expected: []string{"az", "vm", "create", "--name", "my vm", "--resource-group", "myRG"},
			wantErr:  false,
		},
		{
			name:     "command with single quotes",
			input:    "az vm create --name 'my vm' --resource-group myRG",
			expected: []string{"az", "vm", "create", "--name", "my vm", "--resource-group", "myRG"},
			wantErr:  false,
		},
		{
			name:     "command with extra spaces",
			input:    "az  vm   list  --resource-group  myRG",
			expected: []string{"az", "vm", "list", "--resource-group", "myRG"},
			wantErr:  false,
		},
		{
			name:     "interior quotes stripped",
			input:    `az re"st" --url=https://management.azure.com/foo`,
			expected: []string{"az", "rest", "--url=https://management.azure.com/foo"},
			wantErr:  false,
		},
		{
			name:     "quoted flag name reconstructs to bare flag",
			input:    `az rest --u"rl"=https://management.azure.com/`,
			expected: []string{"az", "rest", "--url=https://management.azure.com/"},
			wantErr:  false,
		},
		{
			name:     "empty command",
			input:    "",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "unclosed quote",
			input:    `az vm list --name "unclosed`,
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tokenizeCommand(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("tokenizeCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(result) != len(tt.expected) {
					t.Errorf("tokenizeCommand() got %d args, want %d (%v vs %v)", len(result), len(tt.expected), result, tt.expected)
					return
				}
				for i := range result {
					if result[i] != tt.expected[i] {
						t.Errorf("tokenizeCommand() arg[%d] = %v, want %v", i, result[i], tt.expected[i])
					}
				}
			}
		})
	}
}
