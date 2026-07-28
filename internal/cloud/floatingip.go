package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
)

func ListFloatingIPsForPort(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	portID string,
) ([]topology.FloatingIP, error) {
	allPages, err := floatingips.List(
		client,
		floatingips.ListOpts{PortID: portID},
	).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	items, err := floatingips.ExtractFloatingIPs(allPages)
	if err != nil {
		return nil, err
	}

	result := make([]topology.FloatingIP, len(items))
	for index, item := range items {
		result[index] = topology.FloatingIP{
			ID:                item.ID,
			Status:            item.Status,
			FloatingNetworkID: item.FloatingNetworkID,
			FloatingAddress:   item.FloatingIP,
			FixedAddress:      item.FixedIP,
			PortID:            item.PortID,
			RouterID:          item.RouterID,
		}
	}

	return result, nil
}
