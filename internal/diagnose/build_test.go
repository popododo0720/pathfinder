package diagnose

import (
	"errors"
	"strings"
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

func TestBuildShowsSelectedEndpointIdentity(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Source.Endpoint.FixedIPs = append(
		path.Source.Endpoint.FixedIPs,
		topology.FixedIP{
			Address:  "192.0.2.11",
			SubnetID: "selected-subnet",
		},
	)
	selected := path.Source.Endpoint.FixedIPs[1]
	path.Source.SelectedFixedIP = &selected
	path.Source.Network.Name = "tenant-blue"

	result := Build(Input{Neutron: path})
	var detail string
	for _, hop := range result.Hops {
		if hop.ID == "source-vm" {
			detail = hop.Detail
			break
		}
	}
	if !strings.Contains(detail, "ip=192.0.2.11") ||
		strings.Contains(detail, "ip=10.0.0.10") ||
		!strings.Contains(detail, "network=tenant-blue") {
		t.Fatalf("source identity detail = %q", detail)
	}
}

func TestBuildSameNetworkDifferentSubnetsRequiresRoute(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Destination.Endpoint.FixedIPs[0].SubnetID = "other-subnet"
	path.Destination.Subnets[0].ID = "other-subnet"

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusFail {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	if !hasFinding(result, "transport", StatusFail) {
		t.Fatalf("missing route failure: %v", result.Findings)
	}
}

func TestBuildSameNetworkDifferentSubnetsUsesRouter(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Destination.Endpoint.FixedIPs[0].SubnetID = "other-subnet"
	path.Destination.Subnets[0].ID = "other-subnet"
	path.Routers = []topology.Router{{
		ID:               "router",
		Name:             "router",
		Status:           "ACTIVE",
		AdminStateUp:     true,
		InterfaceSubnets: []string{"network-subnet", "other-subnet"},
	}}

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusPass {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
}

func TestRouteStatusUsesSelectedMultiIPv4Subnets(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	sourceSelected := topology.FixedIP{
		Address:  "192.0.2.10",
		SubnetID: "selected-source-subnet",
	}
	destinationSelected := topology.FixedIP{
		Address:  "198.51.100.20",
		SubnetID: "selected-destination-subnet",
	}
	path.Source.Endpoint.FixedIPs = append(
		path.Source.Endpoint.FixedIPs,
		sourceSelected,
	)
	path.Source.Subnets = append(
		path.Source.Subnets,
		topology.Subnet{ID: sourceSelected.SubnetID},
	)
	path.Source.SelectedFixedIP = &sourceSelected
	path.Destination.Endpoint.FixedIPs = append(
		path.Destination.Endpoint.FixedIPs,
		destinationSelected,
	)
	path.Destination.Subnets = append(
		path.Destination.Subnets,
		topology.Subnet{ID: destinationSelected.SubnetID},
	)
	path.Destination.SelectedFixedIP = &destinationSelected
	path.Routers = []topology.Router{
		{
			Name:         "unselected-router",
			Status:       "ACTIVE",
			AdminStateUp: true,
			InterfaceSubnets: []string{
				"source-network-subnet",
				"destination-network-subnet",
			},
		},
		{
			Name:         "selected-router",
			Status:       "ACTIVE",
			AdminStateUp: true,
			InterfaceSubnets: []string{
				sourceSelected.SubnetID,
				destinationSelected.SubnetID,
			},
		},
	}

	status, label, _ := routeStatus(path)
	if status != StatusPass || label != "Neutron router selected-router" {
		t.Fatalf("route = %s %q, want selected-router", status, label)
	}
}

func TestSecurityEvaluationUsesSelectedMultiIPv4Address(t *testing.T) {
	t.Parallel()

	source := testNeutronPath("network", "network").Source
	destination := testNeutronPath("network", "network").Destination
	sourceSelected := topology.FixedIP{
		Address:  "192.0.2.10",
		SubnetID: "selected-subnet",
	}
	destinationSelected := topology.FixedIP{
		Address:  "192.0.2.20",
		SubnetID: "selected-subnet",
	}
	source.Endpoint.FixedIPs = append(
		source.Endpoint.FixedIPs,
		sourceSelected,
	)
	source.SelectedFixedIP = &sourceSelected
	destination.Endpoint.FixedIPs = append(
		destination.Endpoint.FixedIPs,
		destinationSelected,
	)
	destination.SelectedFixedIP = &destinationSelected
	source.SecurityGroups = []topology.SecurityGroup{{
		Name: "selected-only",
		Rules: []topology.SecurityRule{{
			Direction:      "egress",
			EtherType:      "IPv4",
			RemoteIPPrefix: "192.0.2.20/32",
		}},
	}}

	spec := parsePacketSpec("icmp", source, destination)
	status, _ := evaluateSecurity(
		source,
		destination,
		"egress",
		spec,
	)
	if status != StatusPass {
		t.Fatalf("selected-address security status = %s", status)
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

func TestBuildLiveProbeVerifiesExternalPhysicalPath(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Network.External = true
	path.Source.Network.PhysicalNetwork = "external"
	path.Source.Network.SegmentationID = "192"
	path.Destination.Network.External = true
	path.Destination.Network.PhysicalNetwork = "external"
	path.Destination.Network.SegmentationID = "55"
	probe := topology.ProbeResult{
		Protocol:                  "icmp",
		SourceIP:                  "192.168.0.78",
		DestinationIP:             "192.168.55.148",
		Injected:                  true,
		Delivered:                 true,
		ReplyExpected:             true,
		ReplyGenerationAttempted:  true,
		ReplyGenerated:            true,
		ReplyObservationAttempted: true,
		ReplyObserved:             true,
		Marker:                    "icmp-id:42",
	}
	ovsPath := topology.OVSPath{
		Source: topology.OVSEndpoint{
			Host:      "stack1",
			Interface: "tap-source",
			OFPort:    1,
			LinkState: "up",
		},
		Destination: topology.OVSEndpoint{
			Host:      "stack2",
			Interface: "tap-destination",
			OFPort:    2,
			LinkState: "up",
		},
		Flow:  "icmp,nw_src=192.168.0.78,nw_dst=192.168.55.148",
		Trace: "Datapath actions: output:2",
	}

	result := Build(Input{
		Neutron:        path,
		OVS:            &ovsPath,
		OVSRequested:   true,
		Probe:          &probe,
		ProbeRequested: true,
		Microflow:      "icmp",
	})

	if result.Verdict != StatusPass {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	if !hasHop(result, "transport", StatusPass) {
		t.Fatalf("verified transport hop not found: %v", result.Hops)
	}
	if hasFinding(result, "transport", StatusWarning) {
		t.Fatalf(
			"verified transport still has a warning: %v",
			result.Findings,
		)
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

func TestBuildReportsMostSpecificSubnetHostRoute(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Subnets[0] = topology.Subnet{
		ID:   "source-network-subnet",
		Name: "source-subnet",
		HostRoutes: []topology.HostRoute{
			{
				Destination: "10.0.0.0/8",
				NextHop:     "192.0.2.1",
			},
			{
				Destination: "10.0.0.16/28",
				NextHop:     "192.0.2.2",
			},
		},
	}

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusWarning {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "transport", StatusWarning)
	if !strings.Contains(message, "10.0.0.16/28") ||
		!strings.Contains(message, "192.0.2.2") ||
		!strings.Contains(message, "source-subnet") {
		t.Fatalf("host-route cause missing: %q", message)
	}
}

func TestBuildReportsMoreSpecificHostRouteOnSameSubnet(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Source.Subnets[0] = topology.Subnet{
		ID:   "network-subnet",
		CIDR: "10.0.0.0/24",
		HostRoutes: []topology.HostRoute{{
			Destination: "10.0.0.20/32",
			NextHop:     "10.0.0.254",
		}},
	}

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusWarning {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "transport", StatusWarning)
	if !strings.Contains(message, "10.0.0.20/32") ||
		!strings.Contains(message, "10.0.0.254") {
		t.Fatalf("same-subnet host-route cause missing: %q", message)
	}
}

func TestBuildReportsRouterStaticRoute(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Routers = []topology.Router{
		{
			ID:               "router",
			Name:             "router",
			Status:           "ACTIVE",
			AdminStateUp:     true,
			InterfaceSubnets: []string{"source-network-subnet"},
			Routes: []topology.RouterRoute{
				{
					Destination: "10.0.0.0/8",
					NextHop:     "192.0.2.1",
				},
				{
					Destination: "10.0.0.16/28",
					NextHop:     "192.0.2.2",
				},
			},
		},
	}

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusWarning {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "transport", StatusWarning)
	if !strings.Contains(message, "route 10.0.0.16/28") ||
		!strings.Contains(message, "via 192.0.2.2") ||
		!strings.Contains(message, "router") {
		t.Fatalf("router static-route cause missing: %q", message)
	}
}

func TestBuildFailsWhenStaticRouteRouterIsDown(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Routers = []topology.Router{
		{
			ID:               "router",
			Name:             "router",
			Status:           "DOWN",
			AdminStateUp:     true,
			InterfaceSubnets: []string{"source-network-subnet"},
			Routes: []topology.RouterRoute{
				{
					Destination: "10.0.0.0/8",
					NextHop:     "192.0.2.1",
				},
			},
		},
	}

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusFail {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "transport", StatusFail)
	if !strings.Contains(message, "status=DOWN") {
		t.Fatalf("router failure cause missing: %q", message)
	}
}

func TestBuildOneSidedExternalProviderBoundaryWarns(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Network.External = true
	path.Source.Network.NetworkType = "vlan"
	path.Source.Network.PhysicalNetwork = "external"
	path.Source.Network.SegmentationID = "192"
	path.Destination.Network.NetworkType = "vlan"
	path.Destination.Network.PhysicalNetwork = "external"
	path.Destination.Network.SegmentationID = "55"

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusWarning {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "transport", StatusWarning)
	if !strings.Contains(message, "segment=192") ||
		!strings.Contains(message, "segment=55") {
		t.Fatalf("provider-boundary cause missing: %q", message)
	}
}

func TestBuildProviderBoundaryDoesNotHideEndpointFailure(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Network.External = true
	path.Source.Network.NetworkType = "vlan"
	path.Destination.Network.NetworkType = "vlan"
	path.Destination.Network.Status = "DOWN"

	result := Build(Input{
		Neutron:   path,
		Microflow: "icmp",
	})
	if result.Verdict != StatusFail {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	if !hasFinding(result, "destination-network", StatusFail) {
		t.Fatalf(
			"destination failure was hidden: %v",
			result.Findings,
		)
	}
}

func TestBuildRecognizesExternalToInternalRouterPath(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("external-network", "internal-network")
	path.Source.Network.External = true
	path.Routers = []topology.Router{
		{
			ID:                "router",
			Name:              "router",
			Status:            "ACTIVE",
			AdminStateUp:      true,
			ExternalNetworkID: "external-network",
			InterfaceSubnets:  []string{"internal-network-subnet"},
		},
	}
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

func TestBuildFailsWhenExternalRouterIsDown(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("external-network", "internal-network")
	path.Source.Network.External = true
	path.Routers = []topology.Router{
		{
			ID:                "router",
			Name:              "router",
			Status:            "DOWN",
			AdminStateUp:      true,
			ExternalNetworkID: "external-network",
			InterfaceSubnets:  []string{"internal-network-subnet"},
		},
	}
	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})
	if result.Verdict != StatusFail {
		t.Fatalf("Verdict = %s, findings=%v", result.Verdict, result.Findings)
	}
	if !hasFinding(result, "transport", StatusFail) {
		t.Fatalf("transport failure not found: %v", result.Findings)
	}
	if !strings.Contains(
		findingMessage(result, "transport", StatusFail),
		"status=DOWN",
	) {
		t.Fatalf("router DOWN state missing from findings: %v", result.Findings)
	}
}

func TestBuildIncludesUnknownHopsInFindings(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Source.SecurityGroups = nil
	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})

	if result.Verdict != StatusUnknown {
		t.Fatalf("Verdict = %s, findings=%v", result.Verdict, result.Findings)
	}
	if !hasFinding(result, "source-sg", StatusUnknown) {
		t.Fatalf("source security-group UNKNOWN not found: %v", result.Findings)
	}
}

func TestBuildFailsWhenNetworkIsDown(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	path.Destination.Network.Status = "DOWN"
	result := Build(Input{
		Neutron:   path,
		Microflow: "tcp.dst == 443",
	})
	if result.Verdict != StatusFail {
		t.Fatalf("Verdict = %s", result.Verdict)
	}
	if !hasFinding(result, "destination-network", StatusFail) {
		t.Fatalf(
			"destination network failure not found: %v",
			result.Findings,
		)
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

func TestBuildLetsLiveDeliveryOverrideDroppedPlanTrace(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	ovsPath := topology.OVSPath{
		Source: topology.OVSEndpoint{
			Host:      "stack1",
			Interface: "tap-source",
			OFPort:    1,
			LinkState: "up",
		},
		Destination: topology.OVSEndpoint{
			Host:      "stack2",
			Interface: "tap-destination",
			OFPort:    2,
			LinkState: "up",
		},
		Trace: "Datapath actions: drop",
	}
	probe := topology.ProbeResult{
		Injected:  true,
		Delivered: true,
		Marker:    "icmp-id:42",
	}

	result := Build(Input{
		Neutron:        path,
		OVS:            &ovsPath,
		OVSRequested:   true,
		Probe:          &probe,
		ProbeRequested: true,
	})

	if result.Verdict != StatusWarning {
		t.Fatalf(
			"Verdict = %s, want WARN; findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "ovs-trace", StatusWarning)
	if !strings.Contains(message, "live evidence wins") ||
		!strings.Contains(message, "runtime conntrack") {
		t.Fatalf("OVS trace conflict cause missing: %q", message)
	}
}

func TestBuildLetsObservedDeliveryOverrideIncompleteOVNTrace(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	ovnPath := topology.OVNPath{
		Source: topology.OVNEndpoint{
			PortBindingUUID: "source-binding",
			Up:              true,
			ChassisName:     "stack1",
		},
		Destination: topology.OVNEndpoint{
			PortBindingUUID: "destination-binding",
			Up:              true,
			ChassisName:     "stack2",
		},
		Trace: "drop;",
	}
	probe := topology.ProbeResult{
		Mode:                       "observe",
		SourceObservationAttempted: true,
		SourceObserved:             true,
		Delivered:                  true,
		Marker:                     "ipv4-id:42",
	}

	result := Build(Input{
		Neutron:        path,
		OVN:            &ovnPath,
		OVNRequested:   true,
		Probe:          &probe,
		ProbeRequested: true,
	})

	if result.Verdict != StatusWarning {
		t.Fatalf(
			"Verdict = %s, want WARN; findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	message := findingMessage(result, "ovn-trace", StatusWarning)
	if !strings.Contains(message, "exact observed endpoint-tap delivery") ||
		!strings.Contains(message, "live evidence wins") {
		t.Fatalf("OVN trace conflict cause missing: %q", message)
	}
}

func TestBuildDoesNotHideEndpointHealthFailureBehindLiveEvidence(
	t *testing.T,
) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	ovsPath := topology.OVSPath{
		Source: topology.OVSEndpoint{
			Host:      "stack1",
			Interface: "tap-source",
			OFPort:    1,
			LinkState: "down",
		},
		Destination: topology.OVSEndpoint{
			Host:      "stack2",
			Interface: "tap-destination",
			OFPort:    2,
			LinkState: "up",
		},
		Trace: "Datapath actions: drop",
	}
	probe := topology.ProbeResult{
		Injected:  true,
		Delivered: true,
		Marker:    "icmp-id:42",
	}

	result := Build(Input{
		Neutron:        path,
		OVS:            &ovsPath,
		OVSRequested:   true,
		Probe:          &probe,
		ProbeRequested: true,
	})

	if result.Verdict != StatusFail {
		t.Fatalf(
			"Verdict = %s, want FAIL; findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	if !hasFinding(result, "source-ovs", StatusFail) {
		t.Fatalf("source endpoint health failure was hidden: %v", result.Findings)
	}
	if !hasFinding(result, "ovs-trace", StatusWarning) {
		t.Fatalf("trace conflict was not downgraded: %v", result.Findings)
	}
}

func TestBuildReportsDeliveredLiveProbe(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	probe := topology.ProbeResult{
		Protocol:                  "tcp",
		SourceIP:                  "192.0.2.10",
		DestinationIP:             "192.0.2.20",
		SourcePort:                45000,
		DestinationPort:           443,
		Injected:                  true,
		Delivered:                 true,
		ReplyExpected:             true,
		ReplyGenerationAttempted:  true,
		ReplyGenerated:            true,
		ReplyObservationAttempted: true,
		ReplyObserved:             true,
		Marker:                    "tcp:45000->443",
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
		Microflow:      "tcp.dst == 443",
	})

	if result.Verdict != StatusPass {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	if !hasHop(result, "live-probe", StatusPass) {
		t.Fatalf("successful live-probe hop not found: %v", result.Hops)
	}
	if !hasHop(result, "return-probe", StatusPass) {
		t.Fatalf("successful return-probe hop not found: %v", result.Hops)
	}
	if !hasHop(result, "reply-generation", StatusPass) {
		t.Fatalf("reply-generation hop not found: %v", result.Hops)
	}
}

func TestBuildFailsWhenExpectedReplyIsNotObserved(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	probe := topology.ProbeResult{
		Protocol:                  "icmp",
		Injected:                  true,
		Delivered:                 true,
		ReplyExpected:             true,
		ReplyGenerationAttempted:  true,
		ReplyGenerated:            true,
		ReplyObservationAttempted: true,
		ReplyObserved:             false,
		Marker:                    "icmp-id:42",
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
	})

	if result.Verdict != StatusFail {
		t.Fatalf("Verdict = %s", result.Verdict)
	}
	if !hasHop(result, "return-probe", StatusFail) {
		t.Fatalf("failed return-probe hop not found: %v", result.Hops)
	}
}

func TestBuildPassesCorrelatedObservedTraffic(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	probe := topology.ProbeResult{
		Mode:                       "observe",
		Protocol:                   "icmp",
		SourceIP:                   "10.0.0.10",
		DestinationIP:              "10.0.0.20",
		SourceObservationAttempted: true,
		SourceObserved:             true,
		Delivered:                  true,
		Marker:                     "ipv4-id:42",
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
	})

	if result.Verdict != StatusPass {
		t.Fatalf(
			"Verdict = %s, findings=%v",
			result.Verdict,
			result.Findings,
		)
	}
	if !hasHop(result, "live-probe", StatusPass) {
		t.Fatalf("observed traffic hop not found: %v", result.Hops)
	}
}

func TestBuildObserveProbeVerifiesExternalPhysicalPath(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Network.External = true
	path.Source.Network.PhysicalNetwork = "external"
	path.Source.Network.SegmentationID = "192"
	path.Destination.Network.External = true
	path.Destination.Network.PhysicalNetwork = "external"
	path.Destination.Network.SegmentationID = "55"
	probe := topology.ProbeResult{
		Mode:                       "observe",
		Protocol:                   "icmp",
		SourceIP:                   "192.168.0.78",
		DestinationIP:              "192.168.55.148",
		SourceObservationAttempted: true,
		SourceObserved:             true,
		Delivered:                  true,
		Marker:                     "ipv4-id:42",
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
		Microflow:      "icmp",
	})
	if !hasHop(result, "transport", StatusPass) {
		t.Fatalf("verified transport hop not found: %v", result.Hops)
	}
}

func TestBuildKeepsVerifiedDeliveryWhenReplyCaptureFails(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("source-network", "destination-network")
	path.Source.Network.NetworkType = "vlan"
	path.Source.Network.PhysicalNetwork = "external"
	path.Destination.Network.NetworkType = "vlan"
	path.Destination.Network.PhysicalNetwork = "external"
	probe := topology.ProbeResult{
		Mode:                     "live",
		Protocol:                 "icmp",
		Injected:                 true,
		Delivered:                true,
		ReplyExpected:            true,
		ReplyGenerationAttempted: true,
		FailureStage:             topology.ProbeFailureReplyGeneration,
	}
	probeError := errors.New("tcpdump permission denied")

	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
		ProbeError:     probeError,
		Microflow:      "icmp",
	})

	if !hasHop(result, "transport", StatusPass) {
		t.Fatalf("verified transport was lost: %v", result.Hops)
	}
	if !hasHop(result, "live-probe", StatusPass) {
		t.Fatalf("verified forward delivery was lost: %v", result.Hops)
	}
	if !hasHop(result, "reply-generation", StatusFail) {
		t.Fatalf("reply capture failure was not localized: %v", result.Hops)
	}
	message := findingMessage(
		result,
		"reply-generation",
		StatusFail,
	)
	if !strings.Contains(message, "tcpdump permission denied") {
		t.Fatalf("reply capture cause missing: %q", message)
	}
}

func TestBuildExplainsCaptureFailureAfterInjection(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	probe := topology.ProbeResult{
		Mode:         "live",
		Protocol:     "udp",
		Injected:     true,
		FailureStage: topology.ProbeFailureDeliveryCapture,
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
		ProbeError:     errors.New("tcpdump permission denied"),
		Microflow:      "udp.dst == 53",
	})

	message := findingMessage(result, "live-probe", StatusFail)
	if !strings.Contains(message, "injection succeeded") ||
		!strings.Contains(message, "destination-capture") ||
		!strings.Contains(message, "tcpdump permission denied") {
		t.Fatalf("capture failure progress/cause missing: %q", message)
	}
}

func TestBuildMarksUnattemptedReplyStagesUnknown(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	probe := topology.ProbeResult{
		Mode:          "observe",
		Protocol:      "icmp",
		ReplyExpected: true,
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
		Microflow:      "icmp",
	})
	if !hasHop(result, "reply-generation", StatusUnknown) {
		t.Fatalf("reply-generation hop = %v", result.Hops)
	}
	if !hasHop(result, "return-probe", StatusUnknown) {
		t.Fatalf("return-probe hop = %v", result.Hops)
	}
}

func TestBuildFailsWhenLiveProbeIsNotDelivered(t *testing.T) {
	t.Parallel()

	path := testNeutronPath("network", "network")
	probe := topology.ProbeResult{
		Injected: true,
	}
	result := Build(Input{
		Neutron:        path,
		Probe:          &probe,
		ProbeRequested: true,
	})

	if result.Verdict != StatusFail {
		t.Fatalf("Verdict = %s", result.Verdict)
	}
	if !hasHop(result, "live-probe", StatusFail) {
		t.Fatalf("failed live-probe hop not found: %v", result.Hops)
	}
}

func TestOVNMinimalTraceOutputIsRecognized(t *testing.T) {
	t.Parallel()

	if !ovnTraceHasOutput(`output("port");`) {
		t.Fatal("minimal ovn-trace output was not recognized")
	}
}

func hasHop(report Report, id string, status Status) bool {
	for _, hop := range report.Hops {
		if hop.ID == id && hop.Status == status {
			return true
		}
	}
	return false
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
				PortID:      portID,
				Status:      "ACTIVE",
				DeviceID:    "server-" + portID,
				DeviceOwner: "compute:nova",
				HostID:      host,
				VIFType:     "ovs",
				NetworkID:   network,
				MACAddress:  "fa:16:3e:00:00:01",
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

func findingMessage(
	report Report,
	layer string,
	status Status,
) string {
	for _, finding := range report.Findings {
		if finding.Layer == layer && finding.Status == status {
			return finding.Message
		}
	}
	return ""
}
