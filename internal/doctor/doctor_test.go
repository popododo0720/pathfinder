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
	if runner.failContaining != "" &&
		strings.Contains(command, runner.failContaining) {
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
		CheckNova: func(context.Context) error {
			return nil
		},
	})

	if !hasCheck(checks, "OpenStack authentication", StatusPass) {
		t.Fatalf("OpenStack PASS check missing: %+v", checks)
	}
	if !hasCheck(checks, "OVN Northbound", StatusPass) {
		t.Fatalf("OVN PASS check missing: %+v", checks)
	}
	if !hasCheck(checks, "Nova endpoint", StatusPass) {
		t.Fatalf("Nova PASS check missing: %+v", checks)
	}
	if !hasStatusForCause(checks, StatusFail, "not available") {
		t.Fatalf("remote failure cause missing: %+v", checks)
	}
	if countChecksContaining(checks, "compute-2") != 1 {
		t.Fatalf("SSH root cause was repeated: %+v", checks)
	}
}

func countChecksContaining(checks []Check, value string) int {
	count := 0
	for _, check := range checks {
		if strings.Contains(check.Name, value) ||
			strings.Contains(check.Cause, value) {
			count++
		}
	}
	return count
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

func TestRunChecksEveryRuntimeTool(t *testing.T) {
	runner := &fakeRunner{}
	Run(context.Background(), Options{
		OVNHost:      "control-1",
		HostMappings: map[string]string{"stack1": "compute-1"},
		Runner:       runner,
		CheckOpenStack: func(context.Context) error {
			return nil
		},
		CheckNova: func(context.Context) error {
			return nil
		},
	})

	for _, expected := range []string{
		"control-1 docker exec ovn_northd ovn-nbctl --version",
		"control-1 docker exec ovn_northd ovn-sbctl --version",
		"control-1 docker exec ovn_northd ovn-trace --version",
		"compute-1 sh -c command -v \"$1\" >/dev/null pathfinder-doctor timeout",
		"compute-1 tcpdump -D",
		"compute-1 docker exec openvswitch_vswitchd ovs-vsctl --version",
		"compute-1 docker exec openvswitch_vswitchd ovs-appctl --version",
		"compute-1 docker exec openvswitch_vswitchd ovs-ofctl --version",
	} {
		if !containsCommand(runner.commands, expected) {
			t.Errorf("runtime check %q missing from %v", expected, runner.commands)
		}
	}
}

func TestRunReportsPacketCapturePermissionFailure(t *testing.T) {
	runner := &fakeRunner{failContaining: "tcpdump -D"}
	checks := Run(context.Background(), Options{
		HostMappings: map[string]string{"stack1": "compute-1"},
		Runner:       runner,
		CheckOpenStack: func(context.Context) error {
			return nil
		},
		CheckNova: func(context.Context) error {
			return nil
		},
	})

	if !hasCheck(
		checks,
		"tcpdump capture on compute-1",
		StatusFail,
	) {
		t.Fatalf("tcpdump permission failure missing: %+v", checks)
	}
	if !hasStatusForCause(
		checks,
		StatusFail,
		"check capture permissions",
	) {
		t.Fatalf("tcpdump permission cause missing: %+v", checks)
	}
}

func TestRunReportsNovaEndpointSeparately(t *testing.T) {
	checks := Run(context.Background(), Options{
		Runner: &fakeRunner{},
		CheckOpenStack: func(context.Context) error {
			return nil
		},
		CheckNova: func(context.Context) error {
			return errors.New("compute endpoint missing")
		},
	})

	if !hasCheck(checks, "OpenStack authentication", StatusPass) {
		t.Fatalf("OpenStack PASS check missing: %+v", checks)
	}
	if !hasCheck(checks, "Nova endpoint", StatusWarn) {
		t.Fatalf("Nova warning missing: %+v", checks)
	}
	if !hasStatusForCause(
		checks,
		StatusWarn,
		"compute endpoint missing",
	) {
		t.Fatalf("Nova warning cause missing: %+v", checks)
	}
}

func TestRunSkipsNovaAfterOpenStackFailure(t *testing.T) {
	novaCalls := 0
	checks := Run(context.Background(), Options{
		Runner: &fakeRunner{},
		CheckOpenStack: func(context.Context) error {
			return errors.New("Neutron forbidden")
		},
		CheckNova: func(context.Context) error {
			novaCalls++
			return nil
		},
	})

	if novaCalls != 0 {
		t.Fatalf("Nova check ran after OpenStack failure: %d calls", novaCalls)
	}
	if !hasCheck(checks, "Nova endpoint", StatusWarn) {
		t.Fatalf("skipped Nova warning missing: %+v", checks)
	}
}

func containsCommand(commands []string, expected string) bool {
	for _, command := range commands {
		if strings.Contains(command, expected) {
			return true
		}
	}
	return false
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
