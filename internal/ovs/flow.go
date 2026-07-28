package ovs

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"pathfinder/internal/topology"
)

var (
	ErrNoCompatibleFixedIPs = errors.New(
		"source and destination have no compatible fixed IPs",
	)
	protocolPattern = regexp.MustCompile(
		`(?i)\b(tcp|udp|sctp|icmp4|icmp6)\b`,
	)
	sourcePortPattern = regexp.MustCompile(
		`(?i)\b(?:tcp|udp|sctp)\.src\s*==\s*([0-9]+)`,
	)
	destinationPortPattern = regexp.MustCompile(
		`(?i)\b(?:tcp|udp|sctp)\.dst\s*==\s*([0-9]+)`,
	)
	ethernetDestinationPattern = regexp.MustCompile(
		`(?i)\beth\.dst\s*==\s*([0-9a-f:]{17})`,
	)
)

func BuildTraceFlow(
	source topology.EndpointContext,
	destination topology.EndpointContext,
	sourceOFPort int,
	extra string,
) (string, error) {
	sourceIP, destinationIP, err := compatibleFixedIPs(
		source.Endpoint.FixedIPs,
		destination.Endpoint.FixedIPs,
	)
	if err != nil {
		return "", err
	}

	fields := []string{
		fmt.Sprintf("in_port=%d", sourceOFPort),
		"dl_src=" + source.Endpoint.MACAddress,
	}

	destinationMAC := ""
	if source.Endpoint.SameNetwork(destination.Endpoint) {
		destinationMAC = destination.Endpoint.MACAddress
	} else if matches := ethernetDestinationPattern.FindStringSubmatch(
		extra,
	); len(matches) == 2 {
		destinationMAC = matches[1]
	}
	if destinationMAC != "" {
		fields = append(fields, "dl_dst="+destinationMAC)
	}

	protocol := parseProtocol(extra)
	fields = append(fields, ovsProtocol(sourceIP.Is4(), protocol))
	if sourceIP.Is4() {
		fields = append(
			fields,
			"nw_src="+sourceIP.String(),
			"nw_dst="+destinationIP.String(),
		)
	} else {
		fields = append(
			fields,
			"ipv6_src="+sourceIP.String(),
			"ipv6_dst="+destinationIP.String(),
		)
	}

	switch protocol {
	case "tcp", "udp", "sctp":
		if port := parsePort(sourcePortPattern, extra); port != "" {
			fields = append(fields, "tp_src="+port)
		}
		if port := parsePort(destinationPortPattern, extra); port != "" {
			fields = append(fields, "tp_dst="+port)
		}
	}

	return strings.Join(fields, ","), nil
}

func ovsProtocol(ipv4 bool, protocol string) string {
	if ipv4 {
		switch protocol {
		case "tcp", "udp", "sctp":
			return protocol
		case "icmp4":
			return "icmp"
		default:
			return "ip"
		}
	}

	switch protocol {
	case "tcp", "udp", "sctp":
		return protocol + "6"
	case "icmp6":
		return "icmp6"
	default:
		return "ipv6"
	}
}

func parseProtocol(value string) string {
	matches := protocolPattern.FindStringSubmatch(value)
	if len(matches) != 2 {
		return ""
	}
	return strings.ToLower(matches[1])
}

func parsePort(pattern *regexp.Regexp, value string) string {
	matches := pattern.FindStringSubmatch(value)
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}

func compatibleFixedIPs(
	source []topology.FixedIP,
	destination []topology.FixedIP,
) (netip.Addr, netip.Addr, error) {
	for _, sourceFixedIP := range source {
		sourceIP, err := netip.ParseAddr(sourceFixedIP.Address)
		if err != nil {
			continue
		}
		for _, destinationFixedIP := range destination {
			destinationIP, err := netip.ParseAddr(
				destinationFixedIP.Address,
			)
			if err == nil && sourceIP.Is4() == destinationIP.Is4() {
				return sourceIP, destinationIP, nil
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, ErrNoCompatibleFixedIPs
}
