package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/mtu"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
)

type neutronNetwork struct {
	networks.Network
	external.NetworkExternalExt
	mtu.NetworkMTUExt
	provider.NetworkProviderExt
}

func GetNetwork(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.Network, error) {
	var network neutronNetwork

	err := networks.Get(ctx, client, id).ExtractInto(&network)
	if err != nil {
		return topology.Network{}, err
	}

	return topology.Network{
		ID:              network.ID,
		Name:            network.Name,
		Status:          network.Status,
		External:        network.External,
		MTU:             network.MTU,
		NetworkType:     network.NetworkType,
		PhysicalNetwork: network.PhysicalNetwork,
		SegmentationID:  network.SegmentationID,
		SubnetIDs:       network.Subnets,
	}, nil
}
