package ovn

import (
	"errors"
	"strings"
	"testing"

	"pathfinder/internal/topology"
)

func TestBuildMicroflowSameNetwork(t *testing.T) {
	t.Parallel()

	source := endpointContext(
		"source-port",
		"fa:16:3e:00:00:01",
		"network",
		"10.0.0.10",
	)
	destination := endpointContext(
		"destination-port",
		"fa:16:3e:00:00:02",
		"network",
		"10.0.0.20",
	)

	flow, err := BuildMicroflow(
		source,
		destination,
		"tcp.dst == 443",
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, condition := range []string{
		`inport == "source-port"`,
		"eth.src == fa:16:3e:00:00:01",
		"eth.dst == fa:16:3e:00:00:02",
		"ip4.src == 10.0.0.10",
		"ip4.dst == 10.0.0.20",
		"(tcp.dst == 443)",
	} {
		if !strings.Contains(flow, condition) {
			t.Errorf("flow %q does not contain %q", flow, condition)
		}
	}
}

func TestBuildMicroflowDifferentNetworksOmitsDestinationMAC(
	t *testing.T,
) {
	t.Parallel()

	source := endpointContext(
		"source-port",
		"fa:16:3e:00:00:01",
		"source-network",
		"10.0.0.10",
	)
	destination := endpointContext(
		"destination-port",
		"fa:16:3e:00:00:02",
		"destination-network",
		"192.0.2.20",
	)

	flow, err := BuildMicroflow(source, destination, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(flow, "eth.dst") {
		t.Fatalf("routed flow should not assume destination MAC: %q", flow)
	}
	if !strings.Contains(flow, "(icmp4)") {
		t.Fatalf("default flow should match ICMPv4: %q", flow)
	}
}

func TestBuildMicroflowRejectsDifferentIPFamilies(t *testing.T) {
	t.Parallel()

	source := endpointContext(
		"source-port",
		"fa:16:3e:00:00:01",
		"network",
		"10.0.0.10",
	)
	destination := endpointContext(
		"destination-port",
		"fa:16:3e:00:00:02",
		"network",
		"2001:db8::20",
	)

	_, err := BuildMicroflow(source, destination, "")
	if !errors.Is(err, ErrNoCompatibleFixedIPs) {
		t.Fatalf("BuildMicroflow() error = %v", err)
	}
}

func TestBuildMicroflowUsesSelectedMultiIPv4Addresses(t *testing.T) {
	t.Parallel()

	source := multiAddressEndpointContext(
		"source-port",
		"fa:16:3e:00:00:01",
		"network",
		"10.0.0.10",
		"192.0.2.10",
	)
	destination := multiAddressEndpointContext(
		"destination-port",
		"fa:16:3e:00:00:02",
		"network",
		"10.0.0.20",
		"192.0.2.20",
	)

	flow, err := BuildMicroflow(source, destination, "icmp")
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{
		"ip4.src == 192.0.2.10",
		"ip4.dst == 192.0.2.20",
	} {
		if !strings.Contains(flow, condition) {
			t.Fatalf("flow %q does not contain %q", flow, condition)
		}
	}
	if strings.Contains(flow, "ip4.src == 10.0.0.10") ||
		strings.Contains(flow, "ip4.dst == 10.0.0.20") {
		t.Fatalf("flow used an unselected fixed IP: %q", flow)
	}
}

func endpointContext(
	portID string,
	macAddress string,
	networkID string,
	ipAddress string,
) topology.EndpointContext {
	return topology.EndpointContext{
		Endpoint: topology.Endpoint{
			PortID:     portID,
			MACAddress: macAddress,
			NetworkID:  networkID,
			FixedIPs: []topology.FixedIP{
				{Address: ipAddress},
			},
		},
	}
}

func multiAddressEndpointContext(
	portID string,
	macAddress string,
	networkID string,
	firstAddress string,
	selectedAddress string,
) topology.EndpointContext {
	selected := topology.FixedIP{
		Address:  selectedAddress,
		SubnetID: "selected-subnet",
	}
	return topology.EndpointContext{
		Endpoint: topology.Endpoint{
			PortID:     portID,
			MACAddress: macAddress,
			NetworkID:  networkID,
			FixedIPs: []topology.FixedIP{
				{Address: firstAddress, SubnetID: "first-subnet"},
				selected,
			},
		},
		SelectedFixedIP: &selected,
	}
}
