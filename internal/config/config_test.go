package config

import "testing"

func TestValidateTransport(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		wantErr   bool
	}{
		{name: "stdio", transport: "stdio"},
		{name: "SSE", transport: "sse", wantErr: true},
		{name: "streamable HTTP", transport: "streamable-http", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Transport = tt.transport
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}
