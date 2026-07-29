package diagnose

import (
	"net/netip"
	"strings"
	"testing"

	"pathfinder/internal/topology"
)

func TestNormalizeNeutronNumericProtocols(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"1":   "icmp4",
		"6":   "tcp",
		"17":  "udp",
		"58":  "icmp6",
		"132": "sctp",
	}
	for protocol, expected := range tests {
		if actual := normalizeProtocol(protocol); actual != expected {
			t.Errorf(
				"normalizeProtocol(%q) = %q, want %q",
				protocol,
				actual,
				expected,
			)
		}
	}
}

func TestNumericTCPProtocolMatchesPacket(t *testing.T) {
	t.Parallel()

	matched, unknown := ruleMatches(
		topology.SecurityRule{
			Direction:    "ingress",
			EtherType:    "IPv4",
			Protocol:     "6",
			PortRangeMin: 443,
			PortRangeMax: 443,
		},
		"ingress",
		packetSpec{
			protocol:        "tcp",
			destinationPort: 443,
			ipVersion:       4,
		},
		netip.MustParseAddr("192.0.2.10"),
		nil,
	)
	if !matched || unknown {
		t.Fatalf("numeric TCP rule = matched %t unknown %t", matched, unknown)
	}
}

func TestExplicitICMPTypeZeroDoesNotMeanAnyType(t *testing.T) {
	t.Parallel()

	source, destination := securityTestEndpoints()
	spec := parsePacketSpec("icmp", source, destination)

	explicitReply := topology.SecurityRule{
		Direction:       "ingress",
		EtherType:       "IPv4",
		Protocol:        "1",
		PortRangeMin:    0,
		PortRangeMinSet: true,
	}
	matched, unknown := ruleMatches(
		explicitReply,
		"ingress",
		spec,
		netip.MustParseAddr("192.0.2.10"),
		nil,
	)
	if matched || unknown {
		t.Fatalf(
			"echo-request matched explicit type 0: matched %t unknown %t",
			matched,
			unknown,
		)
	}

	anyICMP := explicitReply
	anyICMP.PortRangeMinSet = false
	matched, unknown = ruleMatches(
		anyICMP,
		"ingress",
		spec,
		netip.MustParseAddr("192.0.2.10"),
		nil,
	)
	if !matched || unknown {
		t.Fatalf(
			"unset ICMP type did not match: matched %t unknown %t",
			matched,
			unknown,
		)
	}
}

func TestExplicitICMPCodeZeroMatchesEchoRequest(t *testing.T) {
	t.Parallel()

	source, destination := securityTestEndpoints()
	spec := parsePacketSpec(
		"icmp4.type == 8 && icmp4.code == 0",
		source,
		destination,
	)
	rule := topology.SecurityRule{
		Direction:       "ingress",
		EtherType:       "IPv4",
		Protocol:        "icmp",
		PortRangeMin:    8,
		PortRangeMinSet: true,
		PortRangeMax:    0,
		PortRangeMaxSet: true,
	}
	matched, unknown := ruleMatches(
		rule,
		"ingress",
		spec,
		netip.MustParseAddr("192.0.2.10"),
		nil,
	)
	if !matched || unknown {
		t.Fatalf(
			"echo-request code 0 = matched %t unknown %t",
			matched,
			unknown,
		)
	}
}

func TestDisabledPortSecurityPassesWithoutSecurityGroups(t *testing.T) {
	t.Parallel()

	disabled := false
	source, destination := securityTestEndpoints()
	destination.Endpoint.PortSecurityEnabled = &disabled
	destination.SecurityGroups = nil

	status, detail := evaluateSecurity(
		destination,
		source,
		"ingress",
		parsePacketSpec("icmp", source, destination),
	)
	if status != StatusPass {
		t.Fatalf("disabled port security status = %s", status)
	}
	if !strings.Contains(detail, "port security is disabled") {
		t.Fatalf("disabled port security cause = %q", detail)
	}
}

func TestEnabledPortSecurityWithoutGroupsRemainsUnknown(t *testing.T) {
	t.Parallel()

	enabled := true
	source, destination := securityTestEndpoints()
	destination.Endpoint.PortSecurityEnabled = &enabled
	destination.SecurityGroups = nil

	status, _ := evaluateSecurity(
		destination,
		source,
		"ingress",
		parsePacketSpec("icmp", source, destination),
	)
	if status != StatusUnknown {
		t.Fatalf("enabled port security status = %s, want UNKNOWN", status)
	}
}

func securityTestEndpoints() (
	topology.EndpointContext,
	topology.EndpointContext,
) {
	source := topology.EndpointContext{
		Endpoint: topology.Endpoint{
			FixedIPs: []topology.FixedIP{{Address: "192.0.2.10"}},
		},
	}
	destination := topology.EndpointContext{
		Endpoint: topology.Endpoint{
			FixedIPs: []topology.FixedIP{{Address: "192.0.2.20"}},
		},
	}
	return source, destination
}
