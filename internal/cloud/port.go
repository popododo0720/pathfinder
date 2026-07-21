package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

func GetPort(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (*ports.Port, error) {
	return ports.Get(ctx, client, id).Extract()
}

func GetEndpoint(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.Endpoint, error) {
	port, err := GetPort(ctx, client, id)
	if err != nil {
		return topology.Endpoint{}, err
	}

	fixedIPs := make([]topology.FixedIP, len(port.FixedIPs))

	for index, fixedIP := range port.FixedIPs {
		fixedIPs[index] = topology.FixedIP{
			Address:  fixedIP.IPAddress,
			SubnetID: fixedIP.SubnetID,
		}
	}

	return topology.Endpoint{
		PortID:     port.ID,
		Name:       port.Name,
		Status:     port.Status,
		MACAddress: port.MACAddress,
		NetworkID:  port.NetworkID,
		FixedIPs:   fixedIPs,
	}, nil
}
