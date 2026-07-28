package execx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Result struct {
	Stdout string
	Stderr string
}

type Runner interface {
	Run(
		ctx context.Context,
		host string,
		name string,
		args ...string,
	) (Result, error)
}

type SSHConfig struct {
	User           string
	Port           int
	IdentityFile   string
	Password       string
	StrictHostKey  bool
	ConnectTimeout int
}

type SystemRunner struct {
	SSH SSHConfig
}

type CommandError struct {
	Host     string
	Command  string
	ExitCode int
	Stderr   string
	Err      error
}

func (err *CommandError) Error() string {
	location := "local"
	if err.Host != "" {
		location = err.Host
	}

	message := fmt.Sprintf(
		"%s command failed: %s",
		location,
		err.Command,
	)
	if err.ExitCode >= 0 {
		message += fmt.Sprintf(" (exit %d)", err.ExitCode)
	}
	if err.Stderr != "" {
		message += ": " + strings.TrimSpace(err.Stderr)
	}
	return message
}

func (err *CommandError) Unwrap() error {
	return err.Err
}

func (runner SystemRunner) Run(
	ctx context.Context,
	host string,
	name string,
	args ...string,
) (Result, error) {
	commandName := name
	commandArgs := args

	if host != "" && host != "local" {
		commandName = "ssh"
		commandArgs = runner.sshArgs(host, name, args)
		if runner.SSH.Password != "" {
			commandName = "sshpass"
			commandArgs = append([]string{"-e", "ssh"}, commandArgs...)
		}
	}

	command := exec.CommandContext(ctx, commandName, commandArgs...)
	if runner.SSH.Password != "" {
		command.Env = append(
			os.Environ(),
			"SSHPASS="+runner.SSH.Password,
		)
	}
	var stdout strings.Builder
	var stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	result := Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err == nil {
		return result, nil
	}

	exitCode := -1
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		exitCode = exitError.ExitCode()
	}

	return result, &CommandError{
		Host:     host,
		Command:  formatCommand(name, args),
		ExitCode: exitCode,
		Stderr:   result.Stderr,
		Err:      err,
	}
}

func (runner SystemRunner) sshArgs(
	host string,
	name string,
	args []string,
) []string {
	timeout := runner.SSH.ConnectTimeout
	if timeout <= 0 {
		timeout = 10
	}

	sshArgs := []string{
		"-o", "ConnectTimeout=" + strconv.Itoa(timeout),
		"-o", "LogLevel=ERROR",
	}
	if runner.SSH.Password == "" {
		sshArgs = append(sshArgs, "-o", "BatchMode=yes")
	}
	if runner.SSH.StrictHostKey {
		sshArgs = append(
			sshArgs,
			"-o",
			"StrictHostKeyChecking=yes",
		)
	} else {
		sshArgs = append(
			sshArgs,
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
		)
	}
	if runner.SSH.Port > 0 && runner.SSH.Port != 22 {
		sshArgs = append(
			sshArgs,
			"-p",
			strconv.Itoa(runner.SSH.Port),
		)
	}
	if runner.SSH.IdentityFile != "" {
		sshArgs = append(
			sshArgs,
			"-i",
			runner.SSH.IdentityFile,
		)
	}

	target := host
	if runner.SSH.User != "" {
		target = runner.SSH.User + "@" + host
	}

	return append(
		sshArgs,
		target,
		"--",
		formatCommand(name, args),
	)
}

func formatCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(name))
	for _, argument := range args {
		parts = append(parts, shellQuote(argument))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
