package topology

import (
	"net/netip"
	"testing"
)

func TestLongestMatchingHostRouteChoosesMostSpecificPrefix(t *testing.T) {
	t.Parallel()

	subnets := []Subnet{
		{
			ID: "source-subnet",
			HostRoutes: []HostRoute{
				{
					Destination: "198.51.0.0/16",
					NextHop:     "192.0.2.1",
				},
				{
					Destination: "198.51.100.0/24",
					NextHop:     "192.0.2.2",
				},
			},
		},
	}

	subnet, route, ok := LongestMatchingHostRoute(
		subnets,
		netip.MustParseAddr("198.51.100.20"),
	)
	if !ok {
		t.Fatal("no matching host route")
	}
	if subnet.ID != "source-subnet" {
		t.Fatalf("subnet = %q", subnet.ID)
	}
	if route.Destination != "198.51.100.0/24" ||
		route.NextHop != "192.0.2.2" {
		t.Fatalf("route = %+v", route)
	}
}

func TestLongestMatchingRouterRouteIgnoresInvalidAndOtherFamilyRoutes(
	t *testing.T,
) {
	t.Parallel()

	route, ok := LongestMatchingRouterRoute(
		[]RouterRoute{
			{Destination: "invalid", NextHop: "192.0.2.1"},
			{Destination: "2001:db8::/32", NextHop: "2001:db8::1"},
			{Destination: "203.0.113.0/24", NextHop: "192.0.2.2"},
		},
		netip.MustParseAddr("203.0.113.10"),
	)
	if !ok {
		t.Fatal("no matching router route")
	}
	if route.Destination != "203.0.113.0/24" {
		t.Fatalf("route = %+v", route)
	}
}

func TestRequiresNextHopForMoreSpecificSameSubnetHostRoute(t *testing.T) {
	t.Parallel()

	source := EndpointContext{
		Endpoint: Endpoint{
			NetworkID: "network",
			FixedIPs: []FixedIP{{
				Address:  "192.0.2.10",
				SubnetID: "subnet",
			}},
		},
		Subnets: []Subnet{{
			ID:   "subnet",
			CIDR: "192.0.2.0/24",
			HostRoutes: []HostRoute{{
				Destination: "192.0.2.20/32",
				NextHop:     "192.0.2.254",
			}},
		}},
	}
	destination := EndpointContext{
		Endpoint: Endpoint{
			NetworkID: "network",
			FixedIPs: []FixedIP{{
				Address:  "192.0.2.20",
				SubnetID: "subnet",
			}},
		},
	}

	if !RequiresNextHop(
		source,
		destination,
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.20"),
	) {
		t.Fatal("more-specific host route did not require its next hop")
	}
}

func TestRequiresNextHopKeepsConnectedRouteOverLessSpecificHostRoute(
	t *testing.T,
) {
	t.Parallel()

	source := EndpointContext{
		Endpoint: Endpoint{
			NetworkID: "network",
			FixedIPs: []FixedIP{{
				Address:  "192.0.2.10",
				SubnetID: "subnet",
			}},
		},
		Subnets: []Subnet{{
			ID:   "subnet",
			CIDR: "192.0.2.0/24",
			HostRoutes: []HostRoute{{
				Destination: "0.0.0.0/0",
				NextHop:     "192.0.2.254",
			}},
		}},
	}
	destination := EndpointContext{
		Endpoint: Endpoint{
			NetworkID: "network",
			FixedIPs: []FixedIP{{
				Address:  "192.0.2.20",
				SubnetID: "subnet",
			}},
		},
	}

	if RequiresNextHop(
		source,
		destination,
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.20"),
	) {
		t.Fatal("less-specific host route overrode the connected subnet")
	}
}

func TestKnownRouterNextHopUsesSourceGatewayInterface(t *testing.T) {
	t.Parallel()

	path := routedTopologyPath()
	path.Routers = []Router{{
		Interfaces: []RouterInterface{{
			SubnetID:   "source-subnet",
			IPAddress:  "192.0.2.1",
			MACAddress: "fa:16:3e:00:00:fe",
		}},
	}}

	nextHop, found := KnownRouterNextHop(path)
	if !found {
		t.Fatal("known router next hop was not found")
	}
	if nextHop.IPAddress != "192.0.2.1" ||
		nextHop.MACAddress != "fa:16:3e:00:00:fe" {
		t.Fatalf("next hop = %+v", nextHop)
	}
}

func TestKnownRouterNextHopUsesHostRouteInterface(t *testing.T) {
	t.Parallel()

	path := routedTopologyPath()
	path.Source.Subnets[0].HostRoutes = []HostRoute{{
		Destination: "198.51.100.0/24",
		NextHop:     "192.0.2.254",
	}}
	path.Routers = []Router{{
		Interfaces: []RouterInterface{{
			SubnetID:   "source-subnet",
			IPAddress:  "192.0.2.254",
			MACAddress: "fa:16:3e:00:00:fd",
		}},
	}}

	nextHop, found := KnownRouterNextHop(path)
	if !found || nextHop.IPAddress != "192.0.2.254" {
		t.Fatalf("next hop = %+v, found=%t", nextHop, found)
	}
}

func routedTopologyPath() NeutronPath {
	return NeutronPath{
		Source: EndpointContext{
			Endpoint: Endpoint{
				NetworkID: "source-network",
				FixedIPs: []FixedIP{{
					Address:  "192.0.2.10",
					SubnetID: "source-subnet",
				}},
			},
			Subnets: []Subnet{{
				ID:        "source-subnet",
				CIDR:      "192.0.2.0/24",
				GatewayIP: "192.0.2.1",
			}},
		},
		Destination: EndpointContext{
			Endpoint: Endpoint{
				NetworkID: "destination-network",
				FixedIPs: []FixedIP{{
					Address:  "198.51.100.20",
					SubnetID: "destination-subnet",
				}},
			},
		},
	}
}
