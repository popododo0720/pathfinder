package cloud

import (
	"context"

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
