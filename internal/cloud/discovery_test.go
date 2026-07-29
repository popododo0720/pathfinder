package cloud

import (
	"testing"

	"pathfinder/internal/topology"
)

func TestApplyFixedIPSelectionPrefersSelectedMultiIPv4Address(
	t *testing.T,
) {
	t.Parallel()

	endpoint := topology.Endpoint{
		FixedIPs: []topology.FixedIP{
			{Address: "192.0.2.10", SubnetID: "subnet-a"},
			{Address: "192.0.2.11", SubnetID: "subnet-b"},
			{Address: "192.0.2.12", SubnetID: "subnet-c"},
		},
	}
	selected, err := applyFixedIPSelection(&endpoint, "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil ||
		selected.Address != "192.0.2.11" ||
		selected.SubnetID != "subnet-b" {
		t.Fatalf("selected fixed IP = %+v", selected)
	}

	want := []string{"192.0.2.11", "192.0.2.10", "192.0.2.12"}
	for index, address := range want {
		if endpoint.FixedIPs[index].Address != address {
			t.Fatalf(
				"FixedIPs = %+v, want stable selected-first order %v",
				endpoint.FixedIPs,
				want,
			)
		}
	}
}

func TestApplyFixedIPSelectionRejectsStaleSelection(t *testing.T) {
	t.Parallel()

	endpoint := topology.Endpoint{
		FixedIPs: []topology.FixedIP{{
			Address:  "192.0.2.10",
			SubnetID: "subnet-a",
		}},
	}
	if _, err := applyFixedIPSelection(
		&endpoint,
		"192.0.2.99",
	); err == nil {
		t.Fatal("stale selected fixed IP was accepted")
	}
}

func TestPreferSubnetPreservesRemainingOrder(t *testing.T) {
	t.Parallel()

	subnets := []topology.Subnet{
		{ID: "subnet-a"},
		{ID: "subnet-b"},
		{ID: "subnet-c"},
	}
	preferSubnet(subnets, "subnet-b")

	want := []string{"subnet-b", "subnet-a", "subnet-c"}
	for index, id := range want {
		if subnets[index].ID != id {
			t.Fatalf("subnets = %+v, want order %v", subnets, want)
		}
	}
}
