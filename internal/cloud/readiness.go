package cloud

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/pagination"
)

func CheckNetworkReadAccess(
	ctx context.Context,
	client *gophercloud.ServiceClient,
) error {
	if client == nil {
		return fmt.Errorf("Neutron client is not available")
	}
	err := ports.List(
		client,
		ports.ListOpts{Limit: 1},
	).EachPage(ctx, func(context.Context, pagination.Page) (bool, error) {
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("read Neutron ports: %w", err)
	}
	return nil
}

func CheckComputeEndpoint(
	networkClient *gophercloud.ServiceClient,
) error {
	if networkClient == nil || networkClient.ProviderClient == nil {
		return fmt.Errorf("authenticated OpenStack provider is not available")
	}
	endpointOptions, err := endpointOptionsFromEnvironment()
	if err != nil {
		return err
	}
	if _, err := openstack.NewComputeV2(
		networkClient.ProviderClient,
		endpointOptions,
	); err != nil {
		return fmt.Errorf("locate Nova compute endpoint: %w", err)
	}
	return nil
}
