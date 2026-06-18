package azcli

import (
	"fmt"
	"strings"
)

// tokenizeCommand splits cmdStr into argv exactly the way the executor will
// hand it to exec.CommandContext: quote-aware, with interior quotes stripped
// and backslash-escapes honored for ", ', and \. Sharing this between the
// validator and the executor prevents tokenizer-divergence bypasses where
// the guard sees one shape and the executor sees another.
func tokenizeCommand(cmdStr string) ([]string, error) {
	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return nil, fmt.Errorf("empty command string")
	}

	args := []string{}
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for i := 0; i < len(cmdStr); i++ {
		ch := rune(cmdStr[i])
		switch {
		case ch == '"' || ch == '\'':
			if !inQuote {
				inQuote = true
				quoteChar = ch
			} else if ch == quoteChar {
				inQuote = false
				quoteChar = 0
			} else {
				current.WriteRune(ch)
			}
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		case ch == '\\' && i+1 < len(cmdStr):
			next := rune(cmdStr[i+1])
			if next == '"' || next == '\'' || next == '\\' {
				current.WriteRune(next)
				i++
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}

	if inQuote {
		return nil, fmt.Errorf("unclosed quote in command string")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("no command found")
	}
	return args, nil
}
