package diagnose

import (
	"testing"

	"pathfinder/internal/topology"
)

func TestBuildSameNetworkPasses(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})
	if result.Verdict != StatusPass {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
}

func TestBuildExternalNetworksWarnsAboutVisibilityBoundary(
	t *testing.T,
) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Network.External = true
	path.Source.Network.PhysicalNetwork = "external"
	path.Source.Network.SegmentationID = "192"
	path.Destination.Network.External = true
	path.Destination.Network.PhysicalNetwork = "external"
	path.Destination.Network.SegmentationID = "55"

	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})
	if result.Verdict != StatusWarning {
		t.Fatalf("Verdict = %s", result.Verdict)
	}
	if !hasFinding(result, "transport", StatusWarning) {
		t.Fatalf("transport warning not found: %v", result.Findings)
	}
}

func TestBuildFailsWhenNoRouteExists(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})
	if result.Verdict != StatusFail {
		t.Fatalf("Verdict = %s", result.Verdict)
	}
	if !hasFinding(result, "transport", StatusFail) {
		t.Fatalf("transport failure not found: %v", result.Findings)
	}
}

func TestBuildFailsWhenDestinationSecurityGroupDenies(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Destination.SecurityGroups[0].Rules = nil
	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})
	if result.Verdict != StatusFail {
		t.Fatalf("Verdict = %s", result.Verdict)
	}
	if !hasFinding(result, "destination-sg", StatusFail) {
		t.Fatalf(
			"destination security failure not found: %v",
			result.Findings,
		)
	}
}

func TestBuildUsesFinalOVSDatapathAction(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	ovsPath := topology.OVSPath{
		Source: topology.OVSEndpoint{
			Host:        "stack1",
			Interface:   "tap-source",
			OFPort:      1,
			LinkState:   "up",
			LogicalPort: "source",
		},
		Destination: topology.OVSEndpoint{
			Host:        "stack2",
			Interface:   "tap-destination",
			OFPort:      2,
			LinkState:   "up",
			LogicalPort: "destination",
		},
		Trace: "Datapath actions: drop\nDatapath actions: output:5",
	}
	result := Build(Input{
		Neutron:      path,
		OVS:          &ovsPath,
		OVSRequested: true,
		Microflow:    "tcp.dst == 443",
	})
	if result.Verdict != StatusPass {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
}

func TestOVNMinimalTraceOutputIsRecognized(t *testing.T) {
	t.Parallel()

	if !ovnTraceHasOutput(`output("port");`) {
		t.Fatal("minimal ovn-trace output was not recognized")
	}
}

func testNeutronPath(
	sourceNetwork string,
	destinationNetwork string,
) topology.NeutronPath {
	allowAll := func(direction string) topology.SecurityRule {
		return topology.SecurityRule{
			Direction: direction,
			EtherType: "IPv4",
		}
	}
	endpoint := func(
		portID string,
		host string,
		network string,
		address string,
	) topology.EndpointContext {
		return topology.EndpointContext{
			Endpoint: topology.Endpoint{
				PortID:     portID,
				Status:     "ACTIVE",
				HostID:     host,
				VIFType:    "ovs",
				NetworkID:  network,
				MACAddress: "fa:16:3e:00:00:01",
				FixedIPs: []topology.FixedIP{
					{
						Address:  address,
						SubnetID: network + "-subnet",
					},
				},
			},
			Network: topology.Network{
				ID:   network,
				Name: network,
				MTU:  1500,
			},
			Subnets: []topology.Subnet{
				{ID: network + "-subnet"},
			},
			SecurityGroups: []topology.SecurityGroup{
				{
					ID:   "default",
					Name: "default",
					Rules: []topology.SecurityRule{
						allowAll("egress"),
						allowAll("ingress"),
					},
				},
			},
		}
	}

	return topology.NeutronPath{
		Source: endpoint(
			"source",
			"stack1",
			sourceNetwork,
			"10.0.0.10",
		),
		Destination: endpoint(
			"destination",
			"stack2",
			destinationNetwork,
			"10.0.0.20",
		),
	}
}

func hasFinding(
	report Report,
	layer string,
	status Status,
) bool {
	for _, finding := range report.Findings {
		if finding.Layer == layer && finding.Status == status {
			return true
		}
	}
	return false
}
