package cloud

import (
	"context"
	"fmt"
	"net/netip"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
)

func DiscoverEndpoint(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	selection topology.EndpointSelection,
) (topology.EndpointContext, error) {
	endpoint, err := GetEndpoint(ctx, client, selection.PortID)
	if err != nil {
		return topology.EndpointContext{}, fmt.Errorf(
			"get port %q: %w",
			selection.PortID,
			err,
		)
	}
	selectedFixedIP, err := applyFixedIPSelection(
		&endpoint,
		selection.IPAddress,
	)
	if err != nil {
		return topology.EndpointContext{}, fmt.Errorf(
			"select fixed IP for port %q: %w",
			selection.PortID,
			err,
		)
	}

	network, err := GetNetwork(ctx, client, endpoint.NetworkID)
	if err != nil {
		return topology.EndpointContext{}, fmt.Errorf(
			"get network %q: %w",
			endpoint.NetworkID,
			err,
		)
	}

	subnetsByID := make(map[string]topology.Subnet)
	for _, fixedIP := range endpoint.FixedIPs {
		if _, exists := subnetsByID[fixedIP.SubnetID]; exists {
			continue
		}

		subnet, err := GetSubnet(ctx, client, fixedIP.SubnetID)
		if err != nil {
			return topology.EndpointContext{}, fmt.Errorf(
				"get subnet %q: %w",
				fixedIP.SubnetID,
				err,
			)
		}
		subnetsByID[subnet.ID] = subnet
	}

	subnetIDs := uniqueStrings(network.SubnetIDs)
	subnets := make([]topology.Subnet, 0, len(subnetsByID))
	for _, subnetID := range subnetIDs {
		if subnet, exists := subnetsByID[subnetID]; exists {
			subnets = append(subnets, subnet)
		}
	}
	for subnetID, subnet := range subnetsByID {
		if !containsString(subnetIDs, subnetID) {
			subnets = append(subnets, subnet)
		}
	}
	if selectedFixedIP != nil {
		preferSubnet(subnets, selectedFixedIP.SubnetID)
	}

	securityGroups := make(
		[]topology.SecurityGroup,
		0,
		len(endpoint.SecurityGroupIDs),
	)
	for _, securityGroupID := range uniqueStrings(
		endpoint.SecurityGroupIDs,
	) {
		securityGroup, err := GetSecurityGroup(
			ctx,
			client,
			securityGroupID,
		)
		if err != nil {
			return topology.EndpointContext{}, fmt.Errorf(
				"get security group %q: %w",
				securityGroupID,
				err,
			)
		}
		securityGroups = append(securityGroups, securityGroup)
	}

	effectiveQoSPolicyID := endpoint.QoSPolicyID
	if effectiveQoSPolicyID == "" {
		effectiveQoSPolicyID = network.QoSPolicyID
	}

	var qosPolicy *topology.QoSPolicy
	if effectiveQoSPolicyID != "" {
		policy, err := GetQoSPolicy(
			ctx,
			client,
			effectiveQoSPolicyID,
		)
		if err != nil {
			return topology.EndpointContext{}, fmt.Errorf(
				"get QoS policy %q: %w",
				effectiveQoSPolicyID,
				err,
			)
		}
		qosPolicy = &policy
	}

	floatingIPs, err := ListFloatingIPsForPort(
		ctx,
		client,
		endpoint.PortID,
	)
	if err != nil {
		return topology.EndpointContext{}, fmt.Errorf(
			"list floating IPs for port %q: %w",
			endpoint.PortID,
			err,
		)
	}

	return topology.EndpointContext{
		Endpoint:        endpoint,
		Network:         network,
		Subnets:         subnets,
		SecurityGroups:  securityGroups,
		QoSPolicy:       qosPolicy,
		FloatingIPs:     floatingIPs,
		SelectedFixedIP: selectedFixedIP,
	}, nil
}

func DiscoverNeutronPath(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	sourceSelection topology.EndpointSelection,
	destinationSelection topology.EndpointSelection,
) (topology.NeutronPath, error) {
	source, err := DiscoverEndpoint(ctx, client, sourceSelection)
	if err != nil {
		return topology.NeutronPath{}, fmt.Errorf("source: %w", err)
	}

	destination, err := DiscoverEndpoint(
		ctx,
		client,
		destinationSelection,
	)
	if err != nil {
		return topology.NeutronPath{}, fmt.Errorf(
			"destination: %w",
			err,
		)
	}

	var subnetIDs []string
	for _, subnet := range source.FlowSubnets() {
		subnetIDs = append(subnetIDs, subnet.ID)
	}
	for _, subnet := range destination.FlowSubnets() {
		subnetIDs = append(subnetIDs, subnet.ID)
	}

	routers, err := DiscoverRouters(ctx, client, subnetIDs)
	if err != nil {
		return topology.NeutronPath{}, fmt.Errorf(
			"discover routers: %w",
			err,
		)
	}

	return topology.NeutronPath{
		Source:      source,
		Destination: destination,
		Routers:     routers,
	}, nil
}

func applyFixedIPSelection(
	endpoint *topology.Endpoint,
	selectedAddress string,
) (*topology.FixedIP, error) {
	if selectedAddress == "" {
		return nil, nil
	}

	selected, err := netip.ParseAddr(selectedAddress)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid selected address %q: %w",
			selectedAddress,
			err,
		)
	}
	for index, fixedIP := range endpoint.FixedIPs {
		candidate, err := netip.ParseAddr(fixedIP.Address)
		if err != nil || candidate != selected {
			continue
		}

		if index > 0 {
			copy(
				endpoint.FixedIPs[1:index+1],
				endpoint.FixedIPs[:index],
			)
			endpoint.FixedIPs[0] = fixedIP
		}
		value := endpoint.FixedIPs[0]
		return &value, nil
	}
	return nil, fmt.Errorf(
		"selected address %s is no longer assigned to the port",
		selected,
	)
}

func preferSubnet(subnets []topology.Subnet, selectedID string) {
	if selectedID == "" {
		return
	}
	for index, subnet := range subnets {
		if subnet.ID != selectedID {
			continue
		}
		if index > 0 {
			copy(subnets[1:index+1], subnets[:index])
			subnets[0] = subnet
		}
		return
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
