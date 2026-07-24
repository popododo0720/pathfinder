package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/portsbinding"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

type neutronPort struct {
	ports.Port
	portsbinding.PortsBindingExt
}

func getPort(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (*neutronPort, error) {
	var port neutronPort

	err := ports.Get(ctx, client, id).ExtractInto(&port)
	if err != nil {
		return nil, err
	}

	return &port, nil
}

func GetEndpoint(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.Endpoint, error) {
	port, err := getPort(ctx, client, id)
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
		PortID:      port.ID,
		Name:        port.Name,
		Status:      port.Status,
		MACAddress:  port.MACAddress,
		NetworkID:   port.NetworkID,
		DeviceID:    port.DeviceID,
		DeviceOwner: port.DeviceOwner,
		HostID:      port.HostID,
		VIFType:     port.VIFType,
		VNICType:    port.VNICType,
		FixedIPs:    fixedIPs,
	}, nil
}
