package topology

import "testing"

func TestEndpointContextFlowSelection(t *testing.T) {
	t.Parallel()

	selected := FixedIP{
		Address:  "192.0.2.11",
		SubnetID: "selected-subnet",
	}
	context := EndpointContext{
		Endpoint: Endpoint{
			FixedIPs: []FixedIP{
				{Address: "192.0.2.10", SubnetID: "first-subnet"},
				selected,
			},
		},
		Subnets: []Subnet{
			{ID: "first-subnet"},
			{ID: "selected-subnet"},
		},
		SelectedFixedIP: &selected,
	}

	fixedIPs := context.FlowFixedIPs()
	if len(fixedIPs) != 1 || fixedIPs[0] != selected {
		t.Fatalf("FlowFixedIPs() = %+v, want only %+v", fixedIPs, selected)
	}
	subnets := context.FlowSubnets()
	if len(subnets) != 1 || subnets[0].ID != "selected-subnet" {
		t.Fatalf(
			"FlowSubnets() = %+v, want only selected-subnet",
			subnets,
		)
	}
}

func TestEndpointContextWithoutSelectionRetainsAllAddresses(t *testing.T) {
	t.Parallel()

	context := EndpointContext{
		Endpoint: Endpoint{
			FixedIPs: []FixedIP{
				{Address: "192.0.2.10", SubnetID: "first-subnet"},
				{Address: "192.0.2.11", SubnetID: "second-subnet"},
			},
		},
		Subnets: []Subnet{
			{ID: "first-subnet"},
			{ID: "second-subnet"},
		},
	}

	if len(context.FlowFixedIPs()) != 2 {
		t.Fatalf("FlowFixedIPs() = %+v", context.FlowFixedIPs())
	}
	if len(context.FlowSubnets()) != 2 {
		t.Fatalf("FlowSubnets() = %+v", context.FlowSubnets())
	}
}
