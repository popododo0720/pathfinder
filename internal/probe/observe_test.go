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

type observeRunner struct {
	mu       sync.Mutex
	commands []string
}

func (runner *observeRunner) Run(
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
		return execx.Result{
			Stdout: "IP (id 4242, proto ICMP), packet",
		}, nil
	}
	return execx.Result{}, nil
}

func TestObserveCorrelatesExistingTrafficWithoutInjection(t *testing.T) {
	t.Parallel()

	runner := &observeRunner{}
	result, err := Observe(
		context.Background(),
		ovs.NewClient(
			runner,
			ovs.Config{Host: "source-host"},
		),
		ovs.NewClient(
			runner,
			ovs.Config{Host: "destination-host"},
		),
		validProbePath(),
		topology.OVSPath{
			Source: topology.OVSEndpoint{
				Interface: "tap-source",
			},
			Destination: topology.OVSEndpoint{
				Interface: "tap-destination",
			},
		},
		"icmp",
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Injected {
		t.Fatal("observe mode injected a packet")
	}
	if !result.SourceObservationAttempted ||
		!result.SourceObserved || !result.Delivered ||
		!result.ReplyGenerated || !result.ReplyObserved {
		t.Fatalf("observe result = %+v", result)
	}
	if result.Marker != "ipv4-id:4242" {
		t.Fatalf("Marker = %q", result.Marker)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	for _, command := range runner.commands {
		if strings.Contains(command, "packet-out") {
			t.Fatalf("observe command injected traffic: %s", command)
		}
	}
}

func TestCapturesCorrelateByIPv4ID(t *testing.T) {
	t.Parallel()

	if !capturesCorrelate(
		"IP (id 42, proto ICMP)",
		"IP (id 42, proto ICMP)",
	) {
		t.Fatal("equal IPv4 IDs did not correlate")
	}
	if capturesCorrelate(
		"IP (id 42, proto ICMP)",
		"IP (id 43, proto ICMP)",
	) {
		t.Fatal("different IPv4 IDs correlated")
	}
}

func TestCapturesCorrelateAcrossPacketWindows(t *testing.T) {
	t.Parallel()

	first := "IP (id 10, proto ICMP)\nIP (id 42, proto ICMP)"
	second := "IP (id 41, proto ICMP)\nIP (id 42, proto ICMP)"
	if marker := correlatedMarker(first, second); marker != "ipv4-id:42" {
		t.Fatalf("correlatedMarker = %q", marker)
	}
}

func TestCapturesWithoutIPv4IDDoNotCorrelate(t *testing.T) {
	t.Parallel()

	if capturesCorrelate("matching packet", "another matching packet") {
		t.Fatal("captures without a correlation key were accepted")
	}
}
