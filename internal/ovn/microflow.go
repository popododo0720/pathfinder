package ovn

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"pathfinder/internal/topology"
)

var ErrNoCompatibleFixedIPs = errors.New(
	"source and destination have no compatible fixed IPs",
)

var plainICMPPattern = regexp.MustCompile(`(?i)\bicmp\b`)

func BuildMicroflow(
	source topology.EndpointContext,
	destination topology.EndpointContext,
	extra string,
) (string, error) {
	sourceIP, destinationIP, err := compatibleFixedIPs(
		source.FlowFixedIPs(),
		destination.FlowFixedIPs(),
	)
	if err != nil {
		return "", err
	}

	conditions := []string{
		fmt.Sprintf(
			`inport == "%s"`,
			source.Endpoint.PortID,
		),
		fmt.Sprintf("eth.src == %s", source.Endpoint.MACAddress),
	}

	if !topology.RequiresNextHop(
		source,
		destination,
		sourceIP,
		destinationIP,
	) {
		conditions = append(
			conditions,
			fmt.Sprintf(
				"eth.dst == %s",
				destination.Endpoint.MACAddress,
			),
		)
	}

	if sourceIP.Is4() {
		conditions = append(
			conditions,
			fmt.Sprintf("ip4.src == %s", sourceIP),
			fmt.Sprintf("ip4.dst == %s", destinationIP),
		)
	} else {
		conditions = append(
			conditions,
			fmt.Sprintf("ip6.src == %s", sourceIP),
			fmt.Sprintf("ip6.dst == %s", destinationIP),
		)
	}

	extra = strings.TrimSpace(extra)
	if extra == "" {
		if sourceIP.Is4() {
			extra = "icmp4"
		} else {
			extra = "icmp6"
		}
	} else if sourceIP.Is4() {
		extra = plainICMPPattern.ReplaceAllString(extra, "icmp4")
	} else {
		extra = plainICMPPattern.ReplaceAllString(extra, "icmp6")
	}
	conditions = append(conditions, "("+extra+")")

	return strings.Join(conditions, " && "), nil
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
			if err != nil {
				continue
			}
			if sourceIP.Is4() == destinationIP.Is4() {
				return sourceIP, destinationIP, nil
			}
		}
	}

	return netip.Addr{}, netip.Addr{}, ErrNoCompatibleFixedIPs
}
