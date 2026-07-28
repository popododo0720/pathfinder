package ovn

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"pathfinder/internal/topology"
)

var ErrNoCompatibleFixedIPs = errors.New(
	"source and destination have no compatible fixed IPs",
)

func BuildMicroflow(
	source topology.EndpointContext,
	destination topology.EndpointContext,
	extra string,
) (string, error) {
	sourceIP, destinationIP, err := compatibleFixedIPs(
		source.Endpoint.FixedIPs,
		destination.Endpoint.FixedIPs,
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

	if source.Endpoint.SameNetwork(destination.Endpoint) {
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

	if strings.TrimSpace(extra) != "" {
		conditions = append(
			conditions,
			"("+strings.TrimSpace(extra)+")",
		)
	}

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
