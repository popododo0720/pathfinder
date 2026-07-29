package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"pathfinder/internal/execx"
	"pathfinder/internal/topology"
)

func TestEffectiveConnectionStatesUsesExplicitSharedDefault(t *testing.T) {
	t.Parallel()

	got := effectiveConnectionStates(nil)
	want := []string{"trk,est"}
	if !slices.Equal(got, want) {
		t.Fatalf("effectiveConnectionStates(nil) = %q, want %q", got, want)
	}
}

func TestEffectiveConnectionStatesPreservesExplicitSequence(t *testing.T) {
	t.Parallel()

	input := []string{"trk,new", "trk,est,rpl"}
	got := effectiveConnectionStates(input)
	if !slices.Equal(got, input) {
		t.Fatalf("effectiveConnectionStates() = %q, want %q", got, input)
	}
	input[0] = "changed"
	if got[0] != "trk,new" {
		t.Fatal("effectiveConnectionStates returned caller-owned storage")
	}
}

type failingProbeCaptureRunner struct{}

func (failingProbeCaptureRunner) Run(
	_ context.Context,
	host string,
	name string,
	args ...string,
) (execx.Result, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.Contains(command, "tcpdump") {
		return execx.Result{}, &execx.CommandError{
			Host:     host,
			Command:  command,
			ExitCode: 1,
			Stderr:   "tcpdump permission denied",
			Err:      errors.New("exit status 1"),
		}
	}
	return execx.Result{}, nil
}

func TestAnalyzeProbePreservesProgressWhenCaptureFails(t *testing.T) {
	t.Parallel()

	path := topology.NeutronPath{
		Source: topology.EndpointContext{
			Endpoint: topology.Endpoint{
				PortID:      "source-port",
				Status:      "ACTIVE",
				NetworkID:   "network",
				MACAddress:  "fa:16:3e:00:00:01",
				DeviceID:    "source-vm",
				DeviceOwner: "compute:nova",
				HostID:      "stack1",
				VIFType:     "ovs",
				FixedIPs: []topology.FixedIP{{
					Address: "192.0.2.10",
				}},
			},
		},
		Destination: topology.EndpointContext{
			Endpoint: topology.Endpoint{
				PortID:      "destination-port",
				Status:      "ACTIVE",
				NetworkID:   "network",
				MACAddress:  "fa:16:3e:00:00:02",
				DeviceID:    "destination-vm",
				DeviceOwner: "compute:nova",
				HostID:      "stack2",
				VIFType:     "ovs",
				FixedIPs: []topology.FixedIP{{
					Address: "192.0.2.20",
				}},
			},
		},
	}
	ovsPath := &topology.OVSPath{
		Source: topology.OVSEndpoint{
			Interface: "tap-source",
			OFPort:    7,
		},
		Destination: topology.OVSEndpoint{
			Interface: "tap-destination",
			OFPort:    8,
		},
	}
	result := analyzeProbe(
		context.Background(),
		failingProbeCaptureRunner{},
		path,
		ovsPath,
		Options{
			Microflow:    "udp.dst == 53",
			ProbeTimeout: 10 * time.Millisecond,
		},
	)
	if result.err == nil {
		t.Fatal("probe capture failure was lost")
	}
	if result.value == nil {
		t.Fatal("partial probe result was discarded")
	}
	if result.value.Mode != "live" || !result.value.Injected {
		t.Fatalf("partial probe = %+v", *result.value)
	}
}
