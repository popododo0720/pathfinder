package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
)

func GetSubnet(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.Subnet, error) {
	subnet, err := subnets.Get(ctx, client, id).Extract()
	if err != nil {
		return topology.Subnet{}, err
	}

	hostRoutes := make([]topology.HostRoute, len(subnet.HostRoutes))
	for index, route := range subnet.HostRoutes {
		hostRoutes[index] = topology.HostRoute{
			Destination: route.DestinationCIDR,
			NextHop:     route.NextHop,
		}
	}

	return topology.Subnet{
		ID:             subnet.ID,
		ProjectID:      subnet.ProjectID,
		NetworkID:      subnet.NetworkID,
		Name:           subnet.Name,
		IPVersion:      subnet.IPVersion,
		CIDR:           subnet.CIDR,
		GatewayIP:      subnet.GatewayIP,
		EnableDHCP:     subnet.EnableDHCP,
		DNSNameservers: append([]string(nil), subnet.DNSNameservers...),
		HostRoutes:     hostRoutes,
	}, nil
}
