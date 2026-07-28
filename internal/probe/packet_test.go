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
