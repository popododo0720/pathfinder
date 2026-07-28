package probe

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"pathfinder/internal/topology"
)

var (
	ErrIPv6Unsupported = errors.New(
		"live packet injection currently supports IPv4 only",
	)
	ErrNextHopMACRequired = errors.New(
		"cross-network live probe requires a next-hop MAC",
	)

	protocolPattern = regexp.MustCompile(
		`(?i)\b(tcp|udp|icmp|icmp4)\b`,
	)
	sourcePortPattern = regexp.MustCompile(
		`(?i)\b(?:tcp|udp)\.src\s*==\s*([0-9]+)`,
	)
	destinationPortPattern = regexp.MustCompile(
		`(?i)\b(?:tcp|udp)\.dst\s*==\s*([0-9]+)`,
	)
	destinationMACPattern = regexp.MustCompile(
		`(?i)\beth\.dst\s*==\s*([0-9a-f:]{17})`,
	)
)

type Packet struct {
	Bytes           []byte
	Protocol        string
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      int
	DestinationPort int
	SourceMAC       net.HardwareAddr
	DestinationMAC  net.HardwareAddr
}

func BuildPacket(
	path topology.NeutronPath,
	microflow string,
) (Packet, error) {
	sourceIP, destinationIP, err := compatibleIPv4(
		path.Source.Endpoint.FixedIPs,
		path.Destination.Endpoint.FixedIPs,
	)
	if err != nil {
		return Packet{}, err
	}
	sourceMAC, err := net.ParseMAC(path.Source.Endpoint.MACAddress)
	if err != nil {
		return Packet{}, fmt.Errorf("parse source MAC: %w", err)
	}
	destinationMAC, err := packetDestinationMAC(path, microflow)
	if err != nil {
		return Packet{}, err
	}

	protocol := parseProtocol(microflow)
	sourcePort := parsePort(sourcePortPattern, microflow)
	destinationPort := parsePort(destinationPortPattern, microflow)
	if sourcePort == 0 {
		sourcePort = 40000 + int(randomUint16()%20000)
	}
	switch protocol {
	case "tcp":
		if destinationPort == 0 {
			destinationPort = 80
		}
	case "udp":
		if destinationPort == 0 {
			destinationPort = 53
		}
	}

	transport, protocolNumber := buildTransport(
		protocol,
		sourceIP,
		destinationIP,
		sourcePort,
		destinationPort,
	)
	ipHeader := buildIPv4Header(
		sourceIP,
		destinationIP,
		protocolNumber,
		len(transport),
	)

	frame := make([]byte, 0, 14+len(ipHeader)+len(transport))
	frame = append(frame, destinationMAC...)
	frame = append(frame, sourceMAC...)
	frame = append(frame, 0x08, 0x00)
	frame = append(frame, ipHeader...)
	frame = append(frame, transport...)
	for len(frame) < 60 {
		frame = append(frame, 0)
	}

	return Packet{
		Bytes:           frame,
		Protocol:        protocol,
		SourceIP:        sourceIP,
		DestinationIP:   destinationIP,
		SourcePort:      sourcePort,
		DestinationPort: destinationPort,
		SourceMAC:       sourceMAC,
		DestinationMAC:  destinationMAC,
	}, nil
}

func (packet Packet) Hex() string {
	return hex.EncodeToString(packet.Bytes)
}

func compatibleIPv4(
	source []topology.FixedIP,
	destination []topology.FixedIP,
) (netip.Addr, netip.Addr, error) {
	for _, sourceFixedIP := range source {
		sourceIP, err := netip.ParseAddr(sourceFixedIP.Address)
		if err != nil || !sourceIP.Is4() {
			continue
		}
		for _, destinationFixedIP := range destination {
			destinationIP, err := netip.ParseAddr(
				destinationFixedIP.Address,
			)
			if err == nil && destinationIP.Is4() {
				return sourceIP, destinationIP, nil
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, ErrIPv6Unsupported
}

func packetDestinationMAC(
	path topology.NeutronPath,
	microflow string,
) (net.HardwareAddr, error) {
	value := ""
	if path.Source.Endpoint.SameNetwork(path.Destination.Endpoint) {
		value = path.Destination.Endpoint.MACAddress
	} else if matches := destinationMACPattern.FindStringSubmatch(
		microflow,
	); len(matches) == 2 {
		value = matches[1]
	}
	if value == "" {
		return nil, fmt.Errorf(
			"%w; add `eth.dst == GATEWAY_MAC` to the microflow",
			ErrNextHopMACRequired,
		)
	}
	address, err := net.ParseMAC(value)
	if err != nil {
		return nil, fmt.Errorf("parse destination MAC: %w", err)
	}
	return address, nil
}

func parseProtocol(microflow string) string {
	matches := protocolPattern.FindStringSubmatch(microflow)
	if len(matches) != 2 {
		return "icmp"
	}
	switch strings.ToLower(matches[1]) {
	case "icmp4":
		return "icmp"
	default:
		return strings.ToLower(matches[1])
	}
}

func parsePort(pattern *regexp.Regexp, microflow string) int {
	matches := pattern.FindStringSubmatch(microflow)
	if len(matches) != 2 {
		return 0
	}
	value, _ := strconv.Atoi(matches[1])
	return value
}

func buildTransport(
	protocol string,
	sourceIP netip.Addr,
	destinationIP netip.Addr,
	sourcePort int,
	destinationPort int,
) ([]byte, byte) {
	switch protocol {
	case "tcp":
		return buildTCP(
			sourceIP,
			destinationIP,
			sourcePort,
			destinationPort,
		), 6
	case "udp":
		return buildUDP(
			sourceIP,
			destinationIP,
			sourcePort,
			destinationPort,
		), 17
	default:
		return buildICMP(), 1
	}
}

func buildIPv4Header(
	sourceIP netip.Addr,
	destinationIP netip.Addr,
	protocol byte,
	payloadLength int,
) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(
		header[2:4],
		uint16(len(header)+payloadLength),
	)
	binary.BigEndian.PutUint16(header[4:6], randomUint16())
	binary.BigEndian.PutUint16(header[6:8], 0x4000)
	header[8] = 64
	header[9] = protocol
	copy(header[12:16], sourceIP.AsSlice())
	copy(header[16:20], destinationIP.AsSlice())
	binary.BigEndian.PutUint16(header[10:12], checksum(header))
	return header
}

func buildTCP(
	sourceIP netip.Addr,
	destinationIP netip.Addr,
	sourcePort int,
	destinationPort int,
) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(header[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint32(
		header[4:8],
		uint32(time.Now().UnixNano()),
	)
	header[12] = 5 << 4
	header[13] = 0x02
	binary.BigEndian.PutUint16(header[14:16], 65535)
	binary.BigEndian.PutUint16(
		header[16:18],
		transportChecksum(sourceIP, destinationIP, 6, header),
	)
	return header
}

func buildUDP(
	sourceIP netip.Addr,
	destinationIP netip.Addr,
	sourcePort int,
	destinationPort int,
) []byte {
	payload := []byte("pathfinder-live-probe")
	packet := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(packet[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(packet[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)))
	copy(packet[8:], payload)
	value := transportChecksum(sourceIP, destinationIP, 17, packet)
	if value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(packet[6:8], value)
	return packet
}

func buildICMP() []byte {
	payload := []byte("pathfinder-live-probe")
	packet := make([]byte, 8+len(payload))
	packet[0] = 8
	binary.BigEndian.PutUint16(packet[4:6], randomUint16())
	binary.BigEndian.PutUint16(packet[6:8], 1)
	copy(packet[8:], payload)
	binary.BigEndian.PutUint16(packet[2:4], checksum(packet))
	return packet
}

func transportChecksum(
	sourceIP netip.Addr,
	destinationIP netip.Addr,
	protocol byte,
	payload []byte,
) uint16 {
	pseudoHeader := make([]byte, 12+len(payload))
	copy(pseudoHeader[0:4], sourceIP.AsSlice())
	copy(pseudoHeader[4:8], destinationIP.AsSlice())
	pseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(
		pseudoHeader[10:12],
		uint16(len(payload)),
	)
	copy(pseudoHeader[12:], payload)
	return checksum(pseudoHeader)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func randomUint16() uint16 {
	var value [2]byte
	if _, err := rand.Read(value[:]); err == nil {
		return binary.BigEndian.Uint16(value[:])
	}
	return uint16(time.Now().UnixNano())
}
