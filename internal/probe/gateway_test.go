package probe

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"pathfinder/internal/execx"
	"pathfinder/internal/ovs"
	"pathfinder/internal/topology"
)

type gatewayRunner struct {
	mu            sync.Mutex
	commands      []string
	captureOutput string
}

func (runner *gatewayRunner) Run(
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
		output := runner.captureOutput
		if output == "" {
			output = "ARP, Reply 192.0.2.1 is-at 00:11:22:33:44:55"
		}
		return execx.Result{
			Stdout: output,
		}, nil
	}
	return execx.Result{}, nil
}

func TestResolveNextHopUsesNeutronRouterInterface(t *testing.T) {
	t.Parallel()

	path := routedProbePath()
	path.Routers = []topology.Router{
		{
			Interfaces: []topology.RouterInterface{
				{
					SubnetID:   "source-subnet",
					IPAddress:  "192.0.2.1",
					MACAddress: "fa:16:3e:00:00:fe",
				},
			},
		},
	}
	nextHop, err := ResolveNextHop(
		context.Background(),
		ovs.NewClient(
			&gatewayRunner{},
			ovs.Config{Host: "stack1"},
		),
		path,
		topology.OVSPath{},
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nextHop.MAC != "fa:16:3e:00:00:fe" {
		t.Fatalf("next hop = %+v", nextHop)
	}
}

func TestResolveNextHopUsesInterfaceMatchingSubnetGateway(t *testing.T) {
	t.Parallel()

	path := routedProbePath()
	path.Routers = []topology.Router{
		{Interfaces: []topology.RouterInterface{{
			SubnetID:   "source-subnet",
			IPAddress:  "192.0.2.254",
			MACAddress: "fa:16:3e:00:00:fd",
		}}},
		{Interfaces: []topology.RouterInterface{{
			SubnetID:   "source-subnet",
			IPAddress:  "192.0.2.1",
			MACAddress: "fa:16:3e:00:00:fe",
		}}},
	}
	nextHop, err := ResolveNextHop(
		context.Background(),
		ovs.NewClient(&gatewayRunner{}, ovs.Config{Host: "stack1"}),
		path,
		topology.OVSPath{},
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nextHop.MAC != "fa:16:3e:00:00:fe" {
		t.Fatalf("next hop = %+v", nextHop)
	}
}

func TestResolveNextHopLearnsProviderGatewayWithARP(t *testing.T) {
	t.Parallel()

	runner := &gatewayRunner{}
	nextHop, err := ResolveNextHop(
		context.Background(),
		ovs.NewClient(
			runner,
			ovs.Config{Host: "stack1", Container: "ovs"},
		),
		routedProbePath(),
		topology.OVSPath{
			Source: topology.OVSEndpoint{
				Interface: "tap-source",
				OFPort:    7,
			},
		},
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nextHop.IP != "192.0.2.1" ||
		nextHop.MAC != "00:11:22:33:44:55" {
		t.Fatalf("next hop = %+v", nextHop)
	}
}

func TestResolveNextHopDoesNotExposeRawCaptureInError(t *testing.T) {
	t.Parallel()

	const rawCapture = "RAW_CAPTURE_MUST_NOT_RENDER"
	_, err := ResolveNextHop(
		context.Background(),
		ovs.NewClient(
			&gatewayRunner{captureOutput: rawCapture},
			ovs.Config{Host: "stack1", Container: "ovs"},
		),
		routedProbePath(),
		topology.OVSPath{
			Source: topology.OVSEndpoint{
				Interface: "tap-source",
				OFPort:    7,
			},
		},
		10*time.Millisecond,
	)
	if err == nil {
		t.Fatal("invalid ARP capture was accepted")
	}
	if strings.Contains(err.Error(), rawCapture) {
		t.Fatalf("raw capture leaked through error: %v", err)
	}
}

func TestBuildARPRequest(t *testing.T) {
	t.Parallel()

	frame, err := buildARPRequest(
		"fa:16:3e:00:00:01",
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 60 {
		t.Fatalf("ARP frame length = %d", len(frame))
	}
	if got := netip.AddrFrom4([4]byte(frame[38:42])); got.String() !=
		"192.0.2.1" {
		t.Fatalf("ARP target = %s", got)
	}
}

func routedProbePath() topology.NeutronPath {
	path := validProbePath()
	path.Source.Endpoint.NetworkID = "source-network"
	path.Source.Endpoint.FixedIPs[0] = topology.FixedIP{
		Address:  "192.0.2.10",
		SubnetID: "source-subnet",
	}
	path.Source.Subnets = []topology.Subnet{
		{
			ID:        "source-subnet",
			GatewayIP: "192.0.2.1",
		},
	}
	path.Destination.Endpoint.NetworkID = "destination-network"
	path.Destination.Endpoint.FixedIPs[0] = topology.FixedIP{
		Address:  "198.51.100.20",
		SubnetID: "destination-subnet",
	}
	return path
}
