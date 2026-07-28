package cloud

import (
	"context"
	"slices"
	"strings"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

type routerInterface struct {
	RouterID string
	PortID   string
	SubnetID string
}

func getRouter(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.Router, error) {
	router, err := routers.Get(ctx, client, id).Extract()
	if err != nil {
		return topology.Router{}, err
	}

	enableSNAT := true
	if router.GatewayInfo.EnableSNAT != nil {
		enableSNAT = *router.GatewayInfo.EnableSNAT
	}

	externalFixedIPs := make(
		[]topology.FixedIP,
		len(router.GatewayInfo.ExternalFixedIPs),
	)
	for index, fixedIP := range router.GatewayInfo.ExternalFixedIPs {
		externalFixedIPs[index] = topology.FixedIP{
			Address:  fixedIP.IPAddress,
			SubnetID: fixedIP.SubnetID,
		}
	}

	routes := make([]topology.RouterRoute, len(router.Routes))
	for index, route := range router.Routes {
		routes[index] = topology.RouterRoute{
			Destination: route.DestinationCIDR,
			NextHop:     route.NextHop,
		}
	}

	return topology.Router{
		ID:                router.ID,
		ProjectID:         router.ProjectID,
		Name:              router.Name,
		Status:            router.Status,
		AdminStateUp:      router.AdminStateUp,
		Distributed:       router.Distributed,
		ExternalNetworkID: router.GatewayInfo.NetworkID,
		EnableSNAT:        enableSNAT,
		ExternalFixedIPs:  externalFixedIPs,
		Routes:            routes,
	}, nil
}

func listRouterInterfacesForSubnet(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	subnetID string,
) ([]routerInterface, error) {
	allPages, err := ports.List(
		client,
		ports.ListOpts{
			FixedIPs: []ports.FixedIPOpts{{SubnetID: subnetID}},
		},
	).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	items, err := ports.ExtractPorts(allPages)
	if err != nil {
		return nil, err
	}

	var result []routerInterface
	for _, item := range items {
		if !isRouterInterfaceOwner(item.DeviceOwner) {
			continue
		}

		for _, fixedIP := range item.FixedIPs {
			if fixedIP.SubnetID != subnetID {
				continue
			}

			result = append(result, routerInterface{
				RouterID: item.DeviceID,
				PortID:   item.ID,
				SubnetID: subnetID,
			})
		}
	}

	return result, nil
}

func isRouterInterfaceOwner(owner string) bool {
	return strings.HasPrefix(owner, "network:router_interface")
}

func DiscoverRouters(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	subnetIDs []string,
) ([]topology.Router, error) {
	routerInterfaces := make(map[string][]routerInterface)

	for _, subnetID := range uniqueStrings(subnetIDs) {
		interfaces, err := listRouterInterfacesForSubnet(
			ctx,
			client,
			subnetID,
		)
		if err != nil {
			return nil, err
		}

		for _, routerInterface := range interfaces {
			routerInterfaces[routerInterface.RouterID] = append(
				routerInterfaces[routerInterface.RouterID],
				routerInterface,
			)
		}
	}

	routerIDs := make([]string, 0, len(routerInterfaces))
	for routerID := range routerInterfaces {
		routerIDs = append(routerIDs, routerID)
	}
	slices.Sort(routerIDs)

	result := make([]topology.Router, 0, len(routerIDs))
	for _, routerID := range routerIDs {
		router, err := getRouter(ctx, client, routerID)
		if err != nil {
			return nil, err
		}

		for _, routerInterface := range routerInterfaces[routerID] {
			router.InterfacePortIDs = append(
				router.InterfacePortIDs,
				routerInterface.PortID,
			)
			router.InterfaceSubnets = append(
				router.InterfaceSubnets,
				routerInterface.SubnetID,
			)
		}

		router.InterfacePortIDs = uniqueStrings(router.InterfacePortIDs)
		router.InterfaceSubnets = uniqueStrings(router.InterfaceSubnets)
		result = append(result, router)
	}

	return result, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}
