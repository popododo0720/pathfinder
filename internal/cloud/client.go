package cloud

import (
	"context"
	"os"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
)

func NewNetworkClient(ctx context.Context) (*gophercloud.ServiceClient, error) {
	authOptions, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		return nil, err
	}

	provider, err := openstack.AuthenticatedClient(ctx, authOptions)
	if err != nil {
		return nil, err
	}

	return openstack.NewNetworkV2(
		provider,
		gophercloud.EndpointOpts{
			Region: os.Getenv("OS_REGION_NAME"),
		},
	)
}
