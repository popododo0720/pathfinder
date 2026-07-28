package execx

import "testing"

func TestShellQuote(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":          "''",
		"simple":    "'simple'",
		"two words": "'two words'",
		"a'b":       "'a'\"'\"'b'",
	}

	for input, expected := range tests {
		if actual := shellQuote(input); actual != expected {
			t.Fatalf(
				"shellQuote(%q) = %q, want %q",
				input,
				actual,
				expected,
			)
		}
	}
}

func TestFormatCommand(t *testing.T) {
	t.Parallel()

	actual := formatCommand(
		"docker",
		[]string{"exec", "ovn northd", "value'quoted"},
	)
	expected := "'docker' 'exec' 'ovn northd' 'value'\"'\"'quoted'"
	if actual != expected {
		t.Fatalf("formatCommand() = %q, want %q", actual, expected)
	}
}
