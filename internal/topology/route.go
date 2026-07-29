package topology

import "net/netip"

func RequiresNextHop(
	source EndpointContext,
	destination EndpointContext,
	sourceIP netip.Addr,
	destinationIP netip.Addr,
) bool {
	if !source.Endpoint.SameNetwork(destination.Endpoint) {
		return true
	}

	sourceSubnetID := subnetIDForAddress(source.Endpoint.FixedIPs, sourceIP)
	for _, subnet := range source.Subnets {
		if sourceSubnetID != "" && subnet.ID != sourceSubnetID {
			continue
		}
		prefix, err := netip.ParsePrefix(subnet.CIDR)
		if err == nil && prefix.Contains(sourceIP) {
			return !prefix.Contains(destinationIP)
		}
	}

	destinationSubnetID := subnetIDForAddress(
		destination.Endpoint.FixedIPs,
		destinationIP,
	)
	if sourceSubnetID != "" && destinationSubnetID != "" {
		return sourceSubnetID != destinationSubnetID
	}
	return false
}

func subnetIDForAddress(fixedIPs []FixedIP, address netip.Addr) string {
	for _, fixedIP := range fixedIPs {
		candidate, err := netip.ParseAddr(fixedIP.Address)
		if err == nil && candidate == address {
			return fixedIP.SubnetID
		}
	}
	return ""
}
