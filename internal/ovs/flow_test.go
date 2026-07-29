package ovs

import (
	"strings"
	"testing"

	"pathfinder/internal/topology"
)

func TestBuildTraceFlow(t *testing.T) {
	t.Parallel()

	source := testEndpoint(
		"source",
		"fa:16:3e:00:00:01",
		"network",
		"10.0.0.10",
	)
	destination := testEndpoint(
		"destination",
		"fa:16:3e:00:00:02",
		"network",
		"10.0.0.20",
	)

	flow, err := BuildTraceFlow(
		source,
		destination,
		7,
		"tcp.src == 12345 && tcp.dst == 443",
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{
		"in_port=7",
		"dl_src=fa:16:3e:00:00:01",
		"dl_dst=fa:16:3e:00:00:02",
		"nw_src=10.0.0.10",
		"nw_dst=10.0.0.20",
		"tcp",
		"tp_src=12345",
		"tp_dst=443",
	} {
		if !strings.Contains(flow, field) {
			t.Errorf("flow %q does not contain %q", flow, field)
		}
	}
}

func TestBuildTraceFlowUsesExplicitNextHopMAC(t *testing.T) {
	t.Parallel()

	source := testEndpoint(
		"source",
		"fa:16:3e:00:00:01",
		"source-network",
		"10.0.0.10",
	)
	destination := testEndpoint(
		"destination",
		"fa:16:3e:00:00:02",
		"destination-network",
		"192.0.2.20",
	)

	flow, err := BuildTraceFlow(
		source,
		destination,
		5,
		"eth.dst == fa:16:3e:ff:ff:ff && udp.dst == 53",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		flow,
		"dl_dst=fa:16:3e:ff:ff:ff",
	) {
		t.Fatalf("flow does not contain explicit next-hop MAC: %q", flow)
	}
	if !strings.Contains(flow, "udp") ||
		!strings.Contains(flow, "tp_dst=53") {
		t.Fatalf("flow does not contain UDP destination port: %q", flow)
	}
}

func TestBuildTraceFlowDefaultsPlainICMPToIPv4ICMP(t *testing.T) {
	t.Parallel()

	source := testEndpoint(
		"source",
		"fa:16:3e:00:00:01",
		"network",
		"10.0.0.10",
	)
	destination := testEndpoint(
		"destination",
		"fa:16:3e:00:00:02",
		"network",
		"10.0.0.20",
	)
	for _, microflow := range []string{"", "icmp"} {
		flow, err := BuildTraceFlow(source, destination, 7, microflow)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(flow, ",icmp,") {
			t.Fatalf("flow for %q = %q", microflow, flow)
		}
	}
}

func TestBuildTraceFlowUsesSelectedMultiIPv4Addresses(t *testing.T) {
	t.Parallel()

	source := multiAddressTestEndpoint(
		"source",
		"fa:16:3e:00:00:01",
		"network",
		"10.0.0.10",
		"192.0.2.10",
	)
	destination := multiAddressTestEndpoint(
		"destination",
		"fa:16:3e:00:00:02",
		"network",
		"10.0.0.20",
		"192.0.2.20",
	)

	flow, err := BuildTraceFlow(source, destination, 7, "icmp")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"nw_src=192.0.2.10",
		"nw_dst=192.0.2.20",
	} {
		if !strings.Contains(flow, field) {
			t.Fatalf("flow %q does not contain %q", flow, field)
		}
	}
	if strings.Contains(flow, "nw_src=10.0.0.10") ||
		strings.Contains(flow, "nw_dst=10.0.0.20") {
		t.Fatalf("flow used an unselected fixed IP: %q", flow)
	}
}

func testEndpoint(
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

func multiAddressTestEndpoint(
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
