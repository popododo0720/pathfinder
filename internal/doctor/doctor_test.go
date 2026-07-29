package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"pathfinder/internal/execx"
)

type fakeRunner struct {
	failContaining string
	commands       []string
}

func (runner *fakeRunner) Run(
	_ context.Context,
	host string,
	name string,
	args ...string,
) (execx.Result, error) {
	command := host + " " + name + " " + strings.Join(args, " ")
	runner.commands = append(runner.commands, command)
	if strings.Contains(command, runner.failContaining) {
		return execx.Result{}, errors.New("not available")
	}
	return execx.Result{Stdout: "version"}, nil
}

func TestRunReportsConcreteRemoteCauses(t *testing.T) {
	runner := &fakeRunner{failContaining: "compute-2"}
	checks := Run(context.Background(), Options{
		OVNHost:         "control-1",
		HostMappings:    map[string]string{"stack1": "compute-1", "stack2": "compute-2"},
		ContainerEngine: "docker",
		OVNContainer:    "ovn_northd",
		OVSContainer:    "openvswitch_vswitchd",
		Runner:          runner,
		CheckOpenStack: func(context.Context) error {
			return nil
		},
	})

	if !hasCheck(checks, "OpenStack authentication", StatusPass) {
		t.Fatalf("OpenStack PASS check missing: %+v", checks)
	}
	if !hasCheck(checks, "OVN Northbound", StatusPass) {
		t.Fatalf("OVN PASS check missing: %+v", checks)
	}
	if !hasStatusForCause(checks, StatusFail, "not available") {
		t.Fatalf("remote failure cause missing: %+v", checks)
	}
}

func TestRunExplainsMissingHosts(t *testing.T) {
	checks := Run(context.Background(), Options{
		Runner: &fakeRunner{},
	})

	if !hasCheck(checks, "OVN central", StatusWarn) {
		t.Fatalf("OVN warning missing: %+v", checks)
	}
	if !hasCheck(checks, "compute hosts", StatusWarn) {
		t.Fatalf("compute warning missing: %+v", checks)
	}
}

func hasCheck(checks []Check, name string, status Status) bool {
	for _, check := range checks {
		if check.Name == name && check.Status == status {
			return true
		}
	}
	return false
}

func hasStatusForCause(
	checks []Check,
	status Status,
	cause string,
) bool {
	for _, check := range checks {
		if check.Status == status && strings.Contains(check.Cause, cause) {
			return true
		}
	}
	return false
}
