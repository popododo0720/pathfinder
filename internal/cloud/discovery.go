package cloud

import (
	"context"
	"fmt"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
)

func DiscoverEndpoint(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	portID string,
) (topology.EndpointContext, error) {
	endpoint, err := GetEndpoint(ctx, client, portID)
	if err != nil {
		return topology.EndpointContext{}, fmt.Errorf(
			"get port %q: %w",
			portID,
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
		Endpoint:       endpoint,
		Network:        network,
		Subnets:        subnets,
		SecurityGroups: securityGroups,
		QoSPolicy:      qosPolicy,
		FloatingIPs:    floatingIPs,
	}, nil
}

func DiscoverNeutronPath(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	sourcePortID string,
	destinationPortID string,
) (topology.NeutronPath, error) {
	source, err := DiscoverEndpoint(ctx, client, sourcePortID)
	if err != nil {
		return topology.NeutronPath{}, fmt.Errorf("source: %w", err)
	}

	destination, err := DiscoverEndpoint(
		ctx,
		client,
		destinationPortID,
	)
	if err != nil {
		return topology.NeutronPath{}, fmt.Errorf(
			"destination: %w",
			err,
		)
	}

	var subnetIDs []string
	for _, subnet := range source.Subnets {
		subnetIDs = append(subnetIDs, subnet.ID)
	}
	for _, subnet := range destination.Subnets {
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

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
