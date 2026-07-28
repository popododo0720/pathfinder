package execx

import (
	"slices"
	"testing"
)

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

func TestSSHArgsEnableConnectionReuse(t *testing.T) {
	t.Parallel()

	runner := SystemRunner{
		SSH: SSHConfig{
			User: "root",
		},
	}
	args := runner.sshArgs("stack1", "hostname", nil)

	for _, expected := range []string{
		"ControlMaster=auto",
		"ControlPersist=60s",
		"ControlPath=/tmp/pathfinder-ssh-%C",
	} {
		if !slices.Contains(args, expected) {
			t.Errorf("ssh args do not contain %q: %v", expected, args)
		}
	}
}

func TestSSHArgsCanDisableConnectionReuse(t *testing.T) {
	t.Parallel()

	runner := SystemRunner{
		SSH: SSHConfig{
			DisableControl: true,
		},
	}
	args := runner.sshArgs("stack1", "hostname", nil)
	if slices.Contains(args, "ControlMaster=auto") {
		t.Fatalf("connection reuse was not disabled: %v", args)
	}
}
