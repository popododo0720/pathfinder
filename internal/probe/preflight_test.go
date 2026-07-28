package probe

import (
	"errors"
	"testing"

	"pathfinder/internal/topology"
)

func TestValidatePathAcceptsDistinctComputePorts(t *testing.T) {
	t.Parallel()

	path := validProbePath()
	if err := ValidatePath(path); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePathRejectsSamePort(t *testing.T) {
	t.Parallel()

	path := validProbePath()
	path.Destination.Endpoint.PortID = path.Source.Endpoint.PortID
	err := ValidatePath(path)
	if !errors.Is(err, ErrPreflightFailed) {
		t.Fatalf("ValidatePath error = %v", err)
	}
}

func TestValidatePathRejectsServicePort(t *testing.T) {
	t.Parallel()

	path := validProbePath()
	path.Destination.Endpoint.DeviceOwner = "network:router_interface"
	err := ValidatePath(path)
	if !errors.Is(err, ErrPreflightFailed) {
		t.Fatalf("ValidatePath error = %v", err)
	}
}

func validProbePath() topology.NeutronPath {
	endpoint := func(id string) topology.EndpointContext {
		return topology.EndpointContext{
			Endpoint: topology.Endpoint{
				PortID:      id,
				Status:      "ACTIVE",
				MACAddress:  "fa:16:3e:00:00:01",
				NetworkID:   "network",
				DeviceID:    "server-" + id,
				DeviceOwner: "compute:nova",
				HostID:      "stack1",
				VIFType:     "ovs",
				FixedIPs: []topology.FixedIP{
					{Address: "192.0.2.10"},
				},
			},
		}
	}
	return topology.NeutronPath{
		Source:      endpoint("source"),
		Destination: endpoint("destination"),
	}
}
