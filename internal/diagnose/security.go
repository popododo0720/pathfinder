package diagnose

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"pathfinder/internal/topology"
)

type packetSpec struct {
	protocol        string
	destinationPort int
	ipVersion       int
	icmpType        int
	icmpTypeSet     bool
	icmpCode        int
	icmpCodeSet     bool
}

var (
	packetProtocolPattern = regexp.MustCompile(
		`(?i)\b(tcp|udp|sctp|icmp|icmp4|icmp6)\b`,
	)
	packetDestinationPortPattern = regexp.MustCompile(
		`(?i)\b(?:tcp|udp|sctp)\.dst\s*==\s*([0-9]+)`,
	)
	packetICMPTypePattern = regexp.MustCompile(
		`(?i)\b(?:icmp|icmp4|icmp6)\.type\s*==\s*([0-9]+)`,
	)
	packetICMPCodePattern = regexp.MustCompile(
		`(?i)\b(?:icmp|icmp4|icmp6)\.code\s*==\s*([0-9]+)`,
	)
)

func parsePacketSpec(
	microflow string,
	source topology.EndpointContext,
	destination topology.EndpointContext,
) packetSpec {
	spec := packetSpec{}
	if matches := packetProtocolPattern.FindStringSubmatch(
		microflow,
	); len(matches) == 2 {
		spec.protocol = strings.ToLower(matches[1])
	}
	if matches := packetDestinationPortPattern.FindStringSubmatch(
		microflow,
	); len(matches) == 2 {
		spec.destinationPort, _ = strconv.Atoi(matches[1])
	}
	if matches := packetICMPTypePattern.FindStringSubmatch(
		microflow,
	); len(matches) == 2 {
		spec.icmpType, _ = strconv.Atoi(matches[1])
		spec.icmpTypeSet = true
	}
	if matches := packetICMPCodePattern.FindStringSubmatch(
		microflow,
	); len(matches) == 2 {
		spec.icmpCode, _ = strconv.Atoi(matches[1])
		spec.icmpCodeSet = true
	}

	sourceIP, destinationIP := compatibleAddresses(
		source.FlowFixedIPs(),
		destination.FlowFixedIPs(),
	)
	if sourceIP.IsValid() && destinationIP.IsValid() {
		if sourceIP.Is4() {
			spec.ipVersion = 4
		} else {
			spec.ipVersion = 6
		}
	}
	if spec.protocol == "" {
		if spec.ipVersion == 6 {
			spec.protocol = "icmp6"
		} else {
			spec.protocol = "icmp4"
		}
	} else if spec.protocol == "icmp" {
		if spec.ipVersion == 6 {
			spec.protocol = "icmp6"
		} else {
			spec.protocol = "icmp4"
		}
	}
	explicitICMPFields := spec.icmpTypeSet || spec.icmpCodeSet
	if !explicitICMPFields && normalizeProtocol(spec.protocol) == "icmp4" {
		if !spec.icmpTypeSet {
			spec.icmpType = 8
			spec.icmpTypeSet = true
		}
		if !spec.icmpCodeSet {
			spec.icmpCodeSet = true
		}
	} else if !explicitICMPFields &&
		normalizeProtocol(spec.protocol) == "icmp6" {
		if !spec.icmpTypeSet {
			spec.icmpType = 128
			spec.icmpTypeSet = true
		}
		if !spec.icmpCodeSet {
			spec.icmpCodeSet = true
		}
	}
	return spec
}

func evaluateSecurity(
	context topology.EndpointContext,
	remote topology.EndpointContext,
	direction string,
	spec packetSpec,
) (Status, string) {
	if context.Endpoint.PortSecurityEnabled != nil &&
		!*context.Endpoint.PortSecurityEnabled {
		return StatusPass, "port security is disabled; security groups are not enforced"
	}
	if len(context.SecurityGroups) == 0 {
		return StatusUnknown, "no security groups returned"
	}

	remoteIP := firstAddress(remote.FlowFixedIPs(), spec.ipVersion)
	remoteGroups := make(map[string]struct{})
	for _, groupID := range remote.Endpoint.SecurityGroupIDs {
		remoteGroups[groupID] = struct{}{}
	}

	indeterminate := false
	for _, group := range context.SecurityGroups {
		for _, rule := range group.Rules {
			matched, unknown := ruleMatches(
				rule,
				direction,
				spec,
				remoteIP,
				remoteGroups,
			)
			if matched {
				return StatusPass, "allowed by security group " + group.Name
			}
			indeterminate = indeterminate || unknown
		}
	}

	if indeterminate {
		return StatusUnknown, "security-group result needs more packet or address-group context"
	}
	return StatusFail, "no security-group rule allows this packet"
}

func ruleMatches(
	rule topology.SecurityRule,
	direction string,
	spec packetSpec,
	remoteIP netip.Addr,
	remoteGroups map[string]struct{},
) (bool, bool) {
	if rule.Direction != direction {
		return false, false
	}
	if spec.ipVersion != 0 {
		expectedEtherType := "IPv4"
		if spec.ipVersion == 6 {
			expectedEtherType = "IPv6"
		}
		if rule.EtherType != "" &&
			!strings.EqualFold(rule.EtherType, expectedEtherType) {
			return false, false
		}
	}

	ruleProtocol := normalizeProtocol(rule.Protocol)
	packetProtocol := normalizeProtocol(spec.protocol)
	if ruleProtocol != "" {
		if packetProtocol == "" {
			return false, true
		}
		if ruleProtocol != packetProtocol {
			return false, false
		}
	}

	rangeMinSet := rule.PortRangeMinSet || rule.PortRangeMin != 0
	rangeMaxSet := rule.PortRangeMaxSet || rule.PortRangeMax != 0
	if ruleProtocol == "icmp4" || ruleProtocol == "icmp6" {
		if rangeMinSet {
			if !spec.icmpTypeSet {
				return false, true
			}
			if spec.icmpType != rule.PortRangeMin {
				return false, false
			}
		}
		if rangeMaxSet {
			if !spec.icmpCodeSet {
				return false, true
			}
			if spec.icmpCode != rule.PortRangeMax {
				return false, false
			}
		}
	} else if rangeMinSet || rangeMaxSet {
		if spec.destinationPort == 0 {
			return false, true
		}
		if (rangeMinSet && spec.destinationPort < rule.PortRangeMin) ||
			(rangeMaxSet && spec.destinationPort > rule.PortRangeMax) {
			return false, false
		}
	}

	switch {
	case rule.RemoteIPPrefix != "":
		prefix, err := netip.ParsePrefix(rule.RemoteIPPrefix)
		if err != nil || !remoteIP.IsValid() {
			return false, true
		}
		return prefix.Contains(remoteIP), false
	case rule.RemoteGroupID != "":
		_, exists := remoteGroups[rule.RemoteGroupID]
		return exists, false
	case rule.RemoteAddressGroupID != "":
		return false, true
	default:
		return true, false
	}
}

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "1", "icmp", "icmp4":
		return "icmp4"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "58", "ipv6-icmp", "icmpv6", "icmp6":
		return "icmp6"
	case "132":
		return "sctp"
	default:
		return strings.ToLower(protocol)
	}
}

func compatibleAddresses(
	source []topology.FixedIP,
	destination []topology.FixedIP,
) (netip.Addr, netip.Addr) {
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
				return sourceIP, destinationIP
			}
		}
	}
	return netip.Addr{}, netip.Addr{}
}

func firstAddress(
	fixedIPs []topology.FixedIP,
	ipVersion int,
) netip.Addr {
	for _, fixedIP := range fixedIPs {
		address, err := netip.ParseAddr(fixedIP.Address)
		if err != nil {
			continue
		}
		if ipVersion == 0 ||
			(ipVersion == 4 && address.Is4()) ||
			(ipVersion == 6 && !address.Is4()) {
			return address
		}
	}
	return netip.Addr{}
}
