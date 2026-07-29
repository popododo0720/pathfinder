package probe

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"pathfinder/internal/execx"
	"pathfinder/internal/ovs"
	"pathfinder/internal/topology"
)

type probeRunner struct {
	mu       sync.Mutex
	commands []string
}

func (runner *probeRunner) Run(
	_ context.Context,
	host string,
	name string,
	args ...string,
) (execx.Result, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	command := host + "|" + name + "|" + strings.Join(args, " ")
	runner.commands = append(runner.commands, command)
	if strings.Contains(command, "tcpdump") {
		if host == "destination-host" {
			return execx.Result{
				Stdout: "generated request matched\n",
			}, nil
		}
		return execx.Result{Stdout: "reply matched\n"}, nil
	}
	return execx.Result{}, nil
}

func TestRunInjectsAndDetectsDelivery(t *testing.T) {
	t.Parallel()

	runner := &probeRunner{}
	sourceClient := ovs.NewClient(
		runner,
		ovs.Config{Host: "source-host", Container: "ovs"},
	)
	destinationClient := ovs.NewClient(
		runner,
		ovs.Config{Host: "destination-host", Container: "ovs"},
	)
	result, err := Run(
		context.Background(),
		sourceClient,
		destinationClient,
		testPath("network", "network"),
		topology.OVSPath{
			Source: topology.OVSEndpoint{
				Interface: "tap-source",
				OFPort:    7,
			},
			Destination: topology.OVSEndpoint{
				Interface: "tap-destination",
				OFPort:    8,
			},
		},
		"udp.dst == 53",
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Injected || !result.Delivered {
		t.Fatalf("probe result = %+v", result)
	}
	if result.SourceObservationAttempted || result.SourceObserved {
		t.Fatalf(
			"live packet-out was reported as a source tap observation: %+v",
			result,
		)
	}
	if result.Method !=
		"ovs-ofctl packet-out + exact tap packet capture" {
		t.Fatalf("Method = %q", result.Method)
	}
	if result.RequestCapture == "" {
		t.Fatal("exact request capture is empty")
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	foundPacketOut := false
	foundFullCaptureWindow := false
	for _, command := range runner.commands {
		if strings.Contains(command, "ovs-ofctl packet-out") {
			foundPacketOut = true
		}
		if strings.Contains(command, "tcpdump") &&
			strings.Contains(command, "1.25s") {
			foundFullCaptureWindow = true
		}
	}
	if !foundPacketOut {
		t.Fatalf("packet-out command was not executed: %v", runner.commands)
	}
	if !foundFullCaptureWindow {
		t.Fatalf(
			"capture timeout did not include warmup: %v",
			runner.commands,
		)
	}
}

func TestCaptureTimeoutPreservesPostWarmupObservationWindow(t *testing.T) {
	t.Parallel()

	if got := captureTimeoutAfterWarmup(2 * time.Second); got !=
		2*time.Second+captureWarmup {
		t.Fatalf("capture timeout = %s", got)
	}
}
