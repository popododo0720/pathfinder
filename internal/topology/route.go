package topology

import "net/netip"

func LongestMatchingHostRoute(
	subnets []Subnet,
	destination netip.Addr,
) (Subnet, HostRoute, bool) {
	var (
		selectedSubnet Subnet
		selectedRoute  HostRoute
		selectedBits   = -1
	)

	for _, subnet := range subnets {
		for _, route := range subnet.HostRoutes {
			prefix, err := netip.ParsePrefix(route.Destination)
			if err != nil ||
				!prefix.Contains(destination) ||
				prefix.Bits() <= selectedBits {
				continue
			}
			selectedSubnet = subnet
			selectedRoute = route
			selectedBits = prefix.Bits()
		}
	}

	return selectedSubnet, selectedRoute, selectedBits >= 0
}

func LongestMatchingRouterRoute(
	routes []RouterRoute,
	destination netip.Addr,
) (RouterRoute, bool) {
	var (
		selectedRoute RouterRoute
		selectedBits  = -1
	)

	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil ||
			!prefix.Contains(destination) ||
			prefix.Bits() <= selectedBits {
			continue
		}
		selectedRoute = route
		selectedBits = prefix.Bits()
	}

	return selectedRoute, selectedBits >= 0
}

func RequiresNextHop(
	source EndpointContext,
	destination EndpointContext,
	sourceIP netip.Addr,
	destinationIP netip.Addr,
) bool {
	if !source.Endpoint.SameNetwork(destination.Endpoint) {
		return true
	}

	sourceSubnetID := subnetIDForAddress(source.FlowFixedIPs(), sourceIP)
	sourceSubnets := subnetsForID(source.FlowSubnets(), sourceSubnetID)
	if hostRouteOverridesConnected(
		sourceSubnets,
		sourceIP,
		destinationIP,
	) {
		return true
	}
	for _, subnet := range sourceSubnets {
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

func hostRouteOverridesConnected(
	subnets []Subnet,
	sourceIP netip.Addr,
	destinationIP netip.Addr,
) bool {
	_, route, found := LongestMatchingHostRoute(subnets, destinationIP)
	if !found {
		return false
	}
	routePrefix, err := netip.ParsePrefix(route.Destination)
	if err != nil {
		return false
	}

	connectedBits := -1
	for _, subnet := range subnets {
		prefix, err := netip.ParsePrefix(subnet.CIDR)
		if err == nil &&
			prefix.Contains(sourceIP) &&
			prefix.Contains(destinationIP) &&
			prefix.Bits() > connectedBits {
			connectedBits = prefix.Bits()
		}
	}
	return connectedBits < 0 || routePrefix.Bits() > connectedBits
}

func subnetsForID(subnets []Subnet, id string) []Subnet {
	if id == "" {
		return subnets
	}
	result := make([]Subnet, 0, 1)
	for _, subnet := range subnets {
		if subnet.ID == id {
			result = append(result, subnet)
		}
	}
	return result
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
