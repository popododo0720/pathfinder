package probe

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"

	"pathfinder/internal/topology"
)

func TestBuildPacketCreatesIPv4TCPSYN(t *testing.T) {
	t.Parallel()

	packet, err := BuildPacket(
		testPath("network", "network"),
		"tcp.dst == 443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Protocol != "tcp" {
		t.Fatalf("Protocol = %q", packet.Protocol)
	}
	if packet.DestinationPort != 443 {
		t.Fatalf("DestinationPort = %d", packet.DestinationPort)
	}
	if len(packet.Bytes) < 60 {
		t.Fatalf("frame length = %d", len(packet.Bytes))
	}
	if got := checksum(packet.Bytes[14:34]); got != 0 {
		t.Fatalf("IPv4 header checksum validation = %#x", got)
	}
	tcpLength := int(binary.BigEndian.Uint16(packet.Bytes[16:18])) - 20
	if got := transportChecksum(
		packet.SourceIP,
		packet.DestinationIP,
		6,
		packet.Bytes[34:34+tcpLength],
	); got != 0 {
		t.Fatalf("TCP checksum validation = %#x", got)
	}
	if packet.Bytes[47]&0x02 == 0 {
		t.Fatal("TCP SYN flag is not set")
	}
	for _, expected := range []string{
		"src host 192.0.2.10",
		"dst host 192.0.2.20",
		"ip[4:2] = " + strconv.Itoa(int(packet.Identifier)),
		"tcp src port",
		"tcp dst port 443",
	} {
		if !strings.Contains(packet.RequestFilter(), expected) {
			t.Fatalf(
				"RequestFilter %q does not contain %q",
				packet.RequestFilter(),
				expected,
			)
		}
	}
	if !packet.ReplyExpected() {
		t.Fatal("TCP reply should be expected")
	}
	if got := binary.BigEndian.Uint32(packet.Bytes[38:42]); got !=
		packet.TCPSequence {
		t.Fatalf("TCP sequence = %d, want %d", got, packet.TCPSequence)
	}
	expectedACK := strconv.FormatUint(
		uint64(packet.TCPSequence+1),
		10,
	)
	if !strings.Contains(packet.ReplyFilter(), "tcp[8:4] = "+expectedACK) {
		t.Fatalf("ReplyFilter = %q", packet.ReplyFilter())
	}
	if !strings.Contains(packet.Marker(), "ipv4-id:") ||
		!strings.Contains(packet.Marker(), "seq:") {
		t.Fatalf("Marker = %q", packet.Marker())
	}
}

func TestBuildPacketCreatesCorrelatedICMPFilters(t *testing.T) {
	t.Parallel()

	packet, err := BuildPacket(
		testPath("network", "network"),
		"icmp",
	)
	if err != nil {
		t.Fatal(err)
	}
	identifier := strconv.Itoa(int(packet.Identifier))
	if !strings.Contains(packet.RequestFilter(), "icmp[4:2] = "+identifier) {
		t.Fatalf("RequestFilter = %q", packet.RequestFilter())
	}
	if !strings.Contains(packet.ReplyFilter(), "icmp[4:2] = "+identifier) {
		t.Fatalf("ReplyFilter = %q", packet.ReplyFilter())
	}
	if packet.SourcePort != 0 || packet.DestinationPort != 0 {
		t.Fatalf(
			"ICMP ports = %d -> %d",
			packet.SourcePort,
			packet.DestinationPort,
		)
	}
}

func TestBuildPacketCreatesExactUDPRequestFilter(t *testing.T) {
	t.Parallel()

	packet, err := BuildPacket(
		testPath("network", "network"),
		"udp.src == 41000 && udp.dst == 53",
	)
	if err != nil {
		t.Fatal(err)
	}
	identifier := strconv.Itoa(int(packet.Identifier))
	if !strings.Contains(packet.RequestFilter(), "ip[4:2] = "+identifier) {
		t.Fatalf("RequestFilter = %q", packet.RequestFilter())
	}
	if !strings.Contains(packet.Marker(), "ipv4-id:"+identifier) {
		t.Fatalf("Marker = %q", packet.Marker())
	}
}

func TestBuildPacketRequiresNextHopMACAcrossNetworks(t *testing.T) {
	t.Parallel()

	_, err := BuildPacket(
		testPath("source-network", "destination-network"),
		"tcp.dst == 443",
	)
	if !errors.Is(err, ErrNextHopMACRequired) {
		t.Fatalf("BuildPacket error = %v", err)
	}
}

func TestBuildPacketRequiresHostRouteNextHopOnSameSubnet(t *testing.T) {
	t.Parallel()

	path := testPath("network", "network")
	path.Source.Endpoint.FixedIPs[0].SubnetID = "subnet"
	path.Source.Subnets = []topology.Subnet{{
		ID:        "subnet",
		CIDR:      "192.0.2.0/24",
		GatewayIP: "192.0.2.1",
		HostRoutes: []topology.HostRoute{{
			Destination: "192.0.2.20/32",
			NextHop:     "192.0.2.254",
		}},
	}}
	path.Destination.Endpoint.FixedIPs[0].SubnetID = "subnet"

	_, err := BuildPacket(path, "icmp")
	if !errors.Is(err, ErrNextHopMACRequired) {
		t.Fatalf("BuildPacket error = %v", err)
	}
}

func TestBuildPacketUsesExplicitNextHopMAC(t *testing.T) {
	t.Parallel()

	packet, err := BuildPacket(
		testPath("source-network", "destination-network"),
		"eth.dst == fa:16:3e:ff:ff:ff && udp.dst == 53",
	)
	if err != nil {
		t.Fatal(err)
	}
	if packet.DestinationMAC.String() != "fa:16:3e:ff:ff:ff" {
		t.Fatalf("DestinationMAC = %s", packet.DestinationMAC)
	}
	if packet.Protocol != "udp" {
		t.Fatalf("Protocol = %q", packet.Protocol)
	}
}

func TestBuildPacketUsesResolvedNextHopMAC(t *testing.T) {
	t.Parallel()

	packet, err := BuildPacketWithDestinationMAC(
		testPath("source-network", "destination-network"),
		"icmp",
		"00:11:22:33:44:55",
	)
	if err != nil {
		t.Fatal(err)
	}
	if packet.DestinationMAC.String() != "00:11:22:33:44:55" {
		t.Fatalf("DestinationMAC = %s", packet.DestinationMAC)
	}
}

func TestBuildPacketRequiresGatewayForDifferentSubnetOnSameNetwork(
	t *testing.T,
) {
	t.Parallel()

	path := testPath("network", "network")
	path.Source.Endpoint.FixedIPs[0].SubnetID = "source-subnet"
	path.Source.Subnets = []topology.Subnet{
		{
			ID:        "source-subnet",
			CIDR:      "192.0.2.0/28",
			GatewayIP: "192.0.2.1",
		},
	}
	path.Destination.Endpoint.FixedIPs[0] = topology.FixedIP{
		Address:  "192.0.2.20",
		SubnetID: "destination-subnet",
	}

	_, err := BuildPacket(path, "icmp")
	if !errors.Is(err, ErrNextHopMACRequired) {
		t.Fatalf("BuildPacket error = %v", err)
	}
}

func TestBuildPacketUsesDirectMACWithinSourceSubnet(t *testing.T) {
	t.Parallel()

	path := testPath("network", "network")
	path.Source.Endpoint.FixedIPs[0].SubnetID = "subnet"
	path.Source.Subnets = []topology.Subnet{
		{ID: "subnet", CIDR: "192.0.2.0/24"},
	}
	path.Destination.Endpoint.FixedIPs[0].SubnetID = "subnet"

	packet, err := BuildPacket(path, "icmp")
	if err != nil {
		t.Fatal(err)
	}
	if packet.DestinationMAC.String() !=
		path.Destination.Endpoint.MACAddress {
		t.Fatalf("DestinationMAC = %s", packet.DestinationMAC)
	}
}

func TestBuildPacketUsesSelectedMultiIPv4Addresses(t *testing.T) {
	t.Parallel()

	path := testPath("network", "network")
	sourceSelected := topology.FixedIP{
		Address:  "192.0.2.11",
		SubnetID: "selected-subnet",
	}
	destinationSelected := topology.FixedIP{
		Address:  "192.0.2.21",
		SubnetID: "selected-subnet",
	}
	path.Source.Endpoint.FixedIPs = append(
		path.Source.Endpoint.FixedIPs,
		sourceSelected,
	)
	path.Source.SelectedFixedIP = &sourceSelected
	path.Source.Subnets = []topology.Subnet{{
		ID:   "selected-subnet",
		CIDR: "192.0.2.0/24",
	}}
	path.Destination.Endpoint.FixedIPs = append(
		path.Destination.Endpoint.FixedIPs,
		destinationSelected,
	)
	path.Destination.SelectedFixedIP = &destinationSelected

	packet, err := BuildPacket(path, "icmp")
	if err != nil {
		t.Fatal(err)
	}
	if packet.SourceIP.String() != "192.0.2.11" ||
		packet.DestinationIP.String() != "192.0.2.21" {
		t.Fatalf(
			"packet addresses = %s -> %s, want selected addresses",
			packet.SourceIP,
			packet.DestinationIP,
		)
	}
}

func testPath(
	sourceNetwork string,
	destinationNetwork string,
) topology.NeutronPath {
	return topology.NeutronPath{
		Source: topology.EndpointContext{
			Endpoint: topology.Endpoint{
				PortID:      "source",
				NetworkID:   sourceNetwork,
				MACAddress:  "fa:16:3e:00:00:01",
				Status:      "ACTIVE",
				DeviceID:    "source-server",
				DeviceOwner: "compute:nova",
				HostID:      "stack1",
				VIFType:     "ovs",
				FixedIPs: []topology.FixedIP{
					{Address: "192.0.2.10"},
				},
			},
		},
		Destination: topology.EndpointContext{
			Endpoint: topology.Endpoint{
				PortID:      "destination",
				NetworkID:   destinationNetwork,
				MACAddress:  "fa:16:3e:00:00:02",
				Status:      "ACTIVE",
				DeviceID:    "destination-server",
				DeviceOwner: "compute:nova",
				HostID:      "stack2",
				VIFType:     "ovs",
				FixedIPs: []topology.FixedIP{
					{Address: "192.0.2.20"},
				},
			},
		},
	}
}
