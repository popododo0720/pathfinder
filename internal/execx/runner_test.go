package execx

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
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
		"ControlPath=/tmp/pathfinder-ssh-%C-accept-new",
		"StrictHostKeyChecking=accept-new",
	} {
		if !slices.Contains(args, expected) {
			t.Errorf("ssh args do not contain %q: %v", expected, args)
		}
	}
}

func TestSSHArgsStrictModeUsesSeparateControlSocket(t *testing.T) {
	t.Parallel()

	runner := SystemRunner{SSH: SSHConfig{StrictHostKey: true}}
	args := runner.sshArgs("stack1", "hostname", nil)
	for _, expected := range []string{
		"ControlPath=/tmp/pathfinder-ssh-%C-strict",
		"StrictHostKeyChecking=yes",
	} {
		if !slices.Contains(args, expected) {
			t.Errorf("strict ssh args do not contain %q: %v", expected, args)
		}
	}
}

func TestSSHArgsInsecureModeDoesNotModifyKnownHosts(t *testing.T) {
	t.Parallel()

	runner := SystemRunner{SSH: SSHConfig{InsecureHostKey: true}}
	args := runner.sshArgs("stack1", "hostname", nil)
	for _, expected := range []string{
		"ControlPath=/tmp/pathfinder-ssh-%C-insecure",
		"StrictHostKeyChecking=no",
		"UserKnownHostsFile=/dev/null",
	} {
		if !slices.Contains(args, expected) {
			t.Errorf("insecure ssh args do not contain %q: %v", expected, args)
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

func TestSystemRunnerCancellationStopsCommandGroup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		50*time.Millisecond,
	)
	defer cancel()
	started := time.Now()
	_, err := (SystemRunner{}).Run(
		ctx,
		"",
		"sh",
		"-c",
		"sleep 30 & wait",
	)
	if err == nil {
		t.Fatal("canceled command succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled command error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled command took %s", elapsed)
	}
}
