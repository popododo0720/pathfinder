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

func TestCapturesRejectSameIPv4IDWithDifferentICMPMarkers(t *testing.T) {
	t.Parallel()

	first := "IP (id 42, proto ICMP), ICMP echo request, id 100, seq 7"
	second := "IP (id 42, proto ICMP), ICMP echo request, id 101, seq 7"
	if capturesCorrelate(first, second) {
		t.Fatal("different ICMP echo identifiers correlated")
	}
}

func TestCapturesCorrelateFullICMPMarker(t *testing.T) {
	t.Parallel()

	capture := "IP (id 42, proto ICMP), ICMP echo request, id 100, seq 7"
	want := "ipv4-id:42,icmp-id:100,icmp-seq:7"
	if marker := correlatedMarker(capture, capture); marker != want {
		t.Fatalf("correlatedMarker = %q, want %q", marker, want)
	}
}

func TestCapturesRejectSameIPv4IDWithDifferentTCPSequence(t *testing.T) {
	t.Parallel()

	first := "IP (id 42, proto TCP), Flags [S], seq 1000, win 64240"
	second := "IP (id 42, proto TCP), Flags [S], seq 2000, win 64240"
	if capturesCorrelate(first, second) {
		t.Fatal("different TCP sequences correlated")
	}
}

func TestCapturesWithoutIPv4IDDoNotCorrelate(t *testing.T) {
	t.Parallel()

	if capturesCorrelate("matching packet", "another matching packet") {
		t.Fatal("captures without a correlation key were accepted")
	}
}

func TestObservationSpecUsesSelectedMultiIPv4Addresses(t *testing.T) {
	t.Parallel()

	path := validProbePath()
	sourceSelected := topology.FixedIP{Address: "192.0.2.11"}
	destinationSelected := topology.FixedIP{Address: "192.0.2.21"}
	path.Source.Endpoint.FixedIPs = append(
		path.Source.Endpoint.FixedIPs,
		sourceSelected,
	)
	path.Source.SelectedFixedIP = &sourceSelected
	path.Destination.Endpoint.FixedIPs = append(
		path.Destination.Endpoint.FixedIPs,
		destinationSelected,
	)
	path.Destination.SelectedFixedIP = &destinationSelected

	spec, err := buildObservationSpec(path, "icmp")
	if err != nil {
		t.Fatal(err)
	}
	if spec.sourceIP != "192.0.2.11" ||
		spec.destinationIP != "192.0.2.21" {
		t.Fatalf(
			"observation addresses = %s -> %s, want selected addresses",
			spec.sourceIP,
			spec.destinationIP,
		)
	}
	if !strings.Contains(spec.requestFilter, "src host 192.0.2.11") ||
		!strings.Contains(spec.requestFilter, "dst host 192.0.2.21") {
		t.Fatalf("request filter = %q", spec.requestFilter)
	}
}
