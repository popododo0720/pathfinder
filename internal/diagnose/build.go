package diagnose

import (
	"fmt"
	"slices"
	"strings"

	"pathfinder/internal/topology"
)

func Build(input Input) Report {
	builder := reportBuilder{verdict: StatusPass}
	packet := parsePacketSpec(
		input.Microflow,
		input.Neutron.Source,
		input.Neutron.Destination,
	)

	sourceVMStatus, sourceVMDetail := endpointStatus(
		input.Neutron.Source.Endpoint,
	)
	builder.addHop(Hop{
		ID:     "source-vm",
		Label:  endpointLabel("source", input.Neutron.Source.Endpoint),
		Status: sourceVMStatus,
		Detail: sourceVMDetail,
	})

	sourceSecurityStatus, sourceSecurityDetail := evaluateSecurity(
		input.Neutron.Source,
		input.Neutron.Destination,
		"egress",
		packet,
	)
	builder.addHop(Hop{
		ID:     "source-sg",
		Label:  "source security-group egress",
		Status: sourceSecurityStatus,
		Detail: sourceSecurityDetail,
	})
	builder.addLink("source-vm", "source-sg", "packet egress", sourceSecurityStatus)

	previous := "source-sg"
	if input.OVS != nil || input.OVSRequested {
		status, detail := observedOVSEndpoint(
			input.OVS,
			input.OVSError,
			true,
		)
		builder.addHop(Hop{
			ID:     "source-ovs",
			Label:  "source compute OVS br-int",
			Status: status,
			Detail: detail,
		})
		builder.addLink(previous, "source-ovs", "tap binding", status)
		previous = "source-ovs"
	}

	if input.OVN != nil || input.OVNRequested {
		status, detail := observedOVNEndpoint(
			input.OVN,
			input.OVNError,
			input.Neutron.Source.Endpoint.HostID,
			true,
		)
		builder.addHop(Hop{
			ID:     "source-ovn",
			Label:  "OVN source logical switch",
			Status: status,
			Detail: detail,
		})
		builder.addLink(previous, "source-ovn", "logical ingress", status)
		previous = "source-ovn"
	}

	routeStatus, routeLabel, routeDetail := routeStatus(input.Neutron)
	if routeStatus == StatusWarning &&
		input.ProbeError == nil &&
		input.Probe != nil &&
		(input.Probe.Injected ||
			(input.Probe.Mode == "observe" &&
				input.Probe.SourceObservationAttempted &&
				input.Probe.SourceObserved)) &&
		input.Probe.Delivered {
		routeStatus = StatusPass
		routeLabel = "external physical path (traffic verified)"
		routeDetail += "; endpoint tap captures confirmed end-to-end delivery"
	}
	builder.addHop(Hop{
		ID:     "transport",
		Label:  routeLabel,
		Status: routeStatus,
		Detail: routeDetail,
	})
	builder.addLink(previous, "transport", "forwarding", routeStatus)
	previous = "transport"

	if input.OVN != nil || input.OVNRequested {
		status, detail := observedOVNEndpoint(
			input.OVN,
			input.OVNError,
			input.Neutron.Destination.Endpoint.HostID,
			false,
		)
		builder.addHop(Hop{
			ID:     "destination-ovn",
			Label:  "OVN destination logical switch",
			Status: status,
			Detail: detail,
		})
		builder.addLink(previous, "destination-ovn", "logical egress", status)
		previous = "destination-ovn"
	}

	if input.OVS != nil || input.OVSRequested {
		status, detail := observedOVSEndpoint(
			input.OVS,
			input.OVSError,
			false,
		)
		builder.addHop(Hop{
			ID:     "destination-ovs",
			Label:  "destination compute OVS br-int",
			Status: status,
			Detail: detail,
		})
		builder.addLink(previous, "destination-ovs", "tap delivery", status)
		previous = "destination-ovs"
	}

	destinationSecurityStatus, destinationSecurityDetail := evaluateSecurity(
		input.Neutron.Destination,
		input.Neutron.Source,
		"ingress",
		packet,
	)
	builder.addHop(Hop{
		ID:     "destination-sg",
		Label:  "destination security-group ingress",
		Status: destinationSecurityStatus,
		Detail: destinationSecurityDetail,
	})
	builder.addLink(
		previous,
		"destination-sg",
		"packet ingress",
		destinationSecurityStatus,
	)

	destinationVMStatus, destinationVMDetail := endpointStatus(
		input.Neutron.Destination.Endpoint,
	)
	builder.addHop(Hop{
		ID: "destination-vm",
		Label: endpointLabel(
			"destination",
			input.Neutron.Destination.Endpoint,
		),
		Status: destinationVMStatus,
		Detail: destinationVMDetail,
	})
	builder.addLink(
		"destination-sg",
		"destination-vm",
		"port delivery",
		destinationVMStatus,
	)
	if input.Probe != nil || input.ProbeRequested {
		probeStatus, probeDetail := observedProbe(
			input.Probe,
			input.ProbeError,
		)
		probeLabel := "live packet delivery"
		if input.Probe != nil && input.Probe.Mode == "observe" {
			probeLabel = "observed traffic delivery"
		}
		builder.addHop(Hop{
			ID:     "live-probe",
			Label:  probeLabel,
			Status: probeStatus,
			Detail: probeDetail,
		})
		builder.addLink(
			"destination-vm",
			"live-probe",
			"end-to-end verification",
			probeStatus,
		)
		if input.Probe != nil && input.Probe.ReplyExpected {
			generatedStatus, generatedDetail := generatedReply(
				input.Probe,
			)
			builder.addHop(Hop{
				ID:     "reply-generation",
				Label:  "destination reply generation",
				Status: generatedStatus,
				Detail: generatedDetail,
			})
			builder.addLink(
				"live-probe",
				"reply-generation",
				"guest reply",
				generatedStatus,
			)
			replyStatus, replyDetail := observedReply(input.Probe)
			builder.addHop(Hop{
				ID:     "return-probe",
				Label:  "return packet delivery",
				Status: replyStatus,
				Detail: replyDetail,
			})
			builder.addLink(
				"reply-generation",
				"return-probe",
				"reply verification",
				replyStatus,
			)
		}
	}

	builder.addTraceFindings(input)
	builder.addNetworkFindings(input.Neutron)
	builder.addMTUFinding(input.Neutron)
	return builder.report()
}

func observedProbe(
	probe *topology.ProbeResult,
	observationError error,
) (Status, string) {
	if observationError != nil {
		return StatusFail, observationError.Error()
	}
	if probe == nil {
		return StatusUnknown, "live probe did not return a result"
	}
	if probe.Mode == "observe" {
		if !probe.SourceObservationAttempted {
			return StatusUnknown,
				"source tap observation was not attempted"
		}
		if !probe.SourceObserved {
			return StatusFail,
				"no matching traffic was observed on the source tap"
		}
	}
	if probe.Mode != "observe" && !probe.Injected {
		return StatusFail, "packet was not injected"
	}
	if !probe.Delivered {
		if probe.Mode == "observe" {
			return StatusFail,
				"matching traffic was observed at the source but not " +
					"correlated at the destination"
		}
		return StatusFail,
			"packet-out was accepted by source OVS, but its exact marker " +
				"was not observed on the destination tap; source tap " +
				"capture is not part of live mode"
	}
	if probe.Mode == "observe" {
		return StatusPass, fmt.Sprintf(
			"%s traffic %s -> %s observed at both taps; marker=%s",
			probe.Protocol,
			probe.SourceIP,
			probe.DestinationIP,
			probe.Marker,
		)
	}
	return StatusPass, fmt.Sprintf(
		"%s %s:%d -> %s:%d delivered after source OVS packet-out; "+
			"source tap capture not attempted; exact marker=%s",
		probe.Protocol,
		probe.SourceIP,
		probe.SourcePort,
		probe.DestinationIP,
		probe.DestinationPort,
		probe.Marker,
	)
}

func generatedReply(probe *topology.ProbeResult) (Status, string) {
	if !probe.ReplyGenerationAttempted {
		return StatusUnknown,
			"reply generation was not tested because forward delivery " +
				"was not verified"
	}
	if probe.ReplyGenerated {
		return StatusPass,
			"matching reply observed leaving the destination tap"
	}
	return StatusFail,
		"request reached the destination tap, but no matching reply " +
			"left the guest"
}

func observedReply(probe *topology.ProbeResult) (Status, string) {
	if !probe.ReplyObservationAttempted {
		return StatusUnknown,
			"return delivery was not tested because a destination reply " +
				"was not verified"
	}
	if probe.ReplyObserved {
		return StatusPass, fmt.Sprintf(
			"reply observed on source tap; filter=%s",
			probe.ReplyFilter,
		)
	}
	if !probe.ReplyGenerated {
		return StatusUnknown,
			"return path was not tested because the destination " +
				"did not generate a matching reply"
	}
	return StatusFail,
		"forward packet arrived, but no matching reply was observed " +
			"on the source tap"
}

type reportBuilder struct {
	hops     []Hop
	links    []Link
	findings []Finding
	verdict  Status
}

func (builder *reportBuilder) addHop(hop Hop) {
	builder.hops = append(builder.hops, hop)
	builder.raise(hop.Status)
	if hop.Status == StatusFail ||
		hop.Status == StatusWarning ||
		hop.Status == StatusUnknown {
		builder.findings = append(builder.findings, Finding{
			Layer:   hop.ID,
			Status:  hop.Status,
			Message: hop.Detail,
		})
	}
}

func (builder *reportBuilder) addLink(
	from string,
	to string,
	label string,
	status Status,
) {
	builder.links = append(builder.links, Link{
		From:   from,
		To:     to,
		Label:  label,
		Status: status,
	})
}

func (builder *reportBuilder) raise(status Status) {
	if severity(status) > severity(builder.verdict) {
		builder.verdict = status
	}
}

func (builder *reportBuilder) addFinding(finding Finding) {
	builder.findings = append(builder.findings, finding)
	builder.raise(finding.Status)
}

func (builder *reportBuilder) report() Report {
	return Report{
		Hops:     builder.hops,
		Links:    builder.links,
		Findings: builder.findings,
		Verdict:  builder.verdict,
	}
}

func severity(status Status) int {
	switch status {
	case StatusFail:
		return 3
	case StatusWarning:
		return 2
	case StatusUnknown:
		return 1
	default:
		return 0
	}
}

func endpointStatus(endpoint topology.Endpoint) (Status, string) {
	switch {
	case endpoint.Status != "ACTIVE":
		return StatusFail, "Neutron port status is " + endpoint.Status
	case endpoint.DeviceOwner != "" &&
		!strings.HasPrefix(endpoint.DeviceOwner, "compute:"):
		return StatusFail, fmt.Sprintf(
			"Neutron port owner=%s is not a VM compute port",
			endpoint.DeviceOwner,
		)
	case endpoint.HostID == "":
		return StatusFail, "Neutron port has no host binding"
	case endpoint.VIFType == "binding_failed":
		return StatusFail, "Neutron VIF binding failed"
	default:
		return StatusPass, fmt.Sprintf(
			"ACTIVE on %s, owner=%s, vif=%s",
			endpoint.HostID,
			endpoint.DeviceOwner,
			endpoint.VIFType,
		)
	}
}

func endpointLabel(role string, endpoint topology.Endpoint) string {
	kind := "VM"
	if endpoint.DeviceOwner != "" &&
		!strings.HasPrefix(endpoint.DeviceOwner, "compute:") {
		kind = "Neutron service port (" + endpoint.DeviceOwner + ")"
	}
	return fmt.Sprintf("%s %s %s", role, kind, endpoint.PortID)
}

func observedOVSEndpoint(
	path *topology.OVSPath,
	observationError error,
	source bool,
) (Status, string) {
	if observationError != nil {
		return StatusFail, observationError.Error()
	}
	if path == nil {
		return StatusUnknown, "OVS inspection was not run"
	}
	endpoint := path.Destination
	if source {
		endpoint = path.Source
	}
	switch {
	case endpoint.Interface == "":
		return StatusFail, "logical port has no OVS interface"
	case endpoint.OFPort <= 0:
		return StatusFail, fmt.Sprintf(
			"%s has invalid ofport %d",
			endpoint.Interface,
			endpoint.OFPort,
		)
	case endpoint.Error != "":
		return StatusFail, endpoint.Interface + ": " + endpoint.Error
	case endpoint.LinkState != "" && endpoint.LinkState != "up":
		return StatusFail, fmt.Sprintf(
			"%s link_state=%s",
			endpoint.Interface,
			endpoint.LinkState,
		)
	default:
		return StatusPass, fmt.Sprintf(
			"%s on %s, ofport=%d, link=%s",
			endpoint.Interface,
			endpoint.Host,
			endpoint.OFPort,
			endpoint.LinkState,
		)
	}
}

func observedOVNEndpoint(
	path *topology.OVNPath,
	observationError error,
	expectedHost string,
	source bool,
) (Status, string) {
	if observationError != nil {
		return StatusFail, observationError.Error()
	}
	if path == nil {
		return StatusUnknown, "OVN inspection was not run"
	}
	endpoint := path.Destination
	if source {
		endpoint = path.Source
	}
	switch {
	case endpoint.PortBindingUUID == "":
		return StatusFail, "logical port has no Southbound Port_Binding"
	case !endpoint.Up:
		return StatusFail, "OVN Port_Binding up=false"
	case endpoint.ChassisName == "":
		return StatusFail, "OVN Port_Binding has no chassis"
	case expectedHost != "" && endpoint.ChassisName != expectedHost:
		return StatusFail, fmt.Sprintf(
			"Neutron host=%s but OVN chassis=%s",
			expectedHost,
			endpoint.ChassisName,
		)
	default:
		return StatusPass, fmt.Sprintf(
			"datapath=%s chassis=%s tunnel_key=%d",
			endpoint.DatapathUUID,
			endpoint.ChassisName,
			endpoint.PortBindingTunnel,
		)
	}
}

func routeStatus(path topology.NeutronPath) (Status, string, string) {
	sourceIP, destinationIP := compatibleAddresses(
		path.Source.Endpoint.FixedIPs,
		path.Destination.Endpoint.FixedIPs,
	)
	if path.Source.Endpoint.SameNetwork(path.Destination.Endpoint) &&
		sourceIP.IsValid() &&
		destinationIP.IsValid() &&
		!topology.RequiresNextHop(
			path.Source,
			path.Destination,
			sourceIP,
			destinationIP,
		) {
		return StatusPass,
			"same Neutron subnet",
			path.Source.Network.Name
	}

	sourceSubnets := subnetSet(path.Source.Subnets)
	destinationSubnets := subnetSet(path.Destination.Subnets)
	for _, router := range path.Routers {
		sourceAttached := intersects(
			sourceSubnets,
			router.InterfaceSubnets,
		)
		destinationAttached := intersects(
			destinationSubnets,
			router.InterfaceSubnets,
		)
		if sourceAttached && destinationAttached {
			status := StatusPass
			if !router.AdminStateUp || router.Status != "ACTIVE" {
				status = StatusFail
			}
			return status,
				"Neutron router " + router.Name,
				fmt.Sprintf(
					"status=%s admin_up=%t",
					router.Status,
					router.AdminStateUp,
				)
		}
		if sourceAttached &&
			router.ExternalNetworkID == path.Destination.Network.ID {
			status := StatusPass
			if !router.AdminStateUp || router.Status != "ACTIVE" {
				status = StatusFail
			}
			return status,
				"Neutron router to external network",
				routerStateDetail(router)
		}
		if destinationAttached &&
			router.ExternalNetworkID == path.Source.Network.ID {
			status := StatusPass
			if !router.AdminStateUp || router.Status != "ACTIVE" {
				status = StatusFail
			}
			return status,
				"external network to Neutron router",
				routerStateDetail(router)
		}
	}

	if path.Source.Network.External &&
		path.Destination.Network.External {
		return StatusWarning,
			"external physical network boundary",
			fmt.Sprintf(
				"OpenStack sees provider %s/VLAN %s -> %s/VLAN %s; external switch/router forwarding is not observable",
				path.Source.Network.PhysicalNetwork,
				path.Source.Network.SegmentationID,
				path.Destination.Network.PhysicalNetwork,
				path.Destination.Network.SegmentationID,
			)
	}

	return StatusFail,
		"no Neutron route",
		"no router connects the source and destination subnets"
}

func routerLabel(router topology.Router) string {
	if router.Name != "" {
		return router.Name
	}
	return router.ID
}

func routerStateDetail(router topology.Router) string {
	return fmt.Sprintf(
		"%s status=%s admin_up=%t",
		routerLabel(router),
		router.Status,
		router.AdminStateUp,
	)
}

func subnetSet(subnets []topology.Subnet) map[string]struct{} {
	result := make(map[string]struct{}, len(subnets))
	for _, subnet := range subnets {
		result[subnet.ID] = struct{}{}
	}
	return result
}

func intersects(values map[string]struct{}, candidates []string) bool {
	return slices.ContainsFunc(candidates, func(candidate string) bool {
		_, exists := values[candidate]
		return exists
	})
}

func (builder *reportBuilder) addTraceFindings(input Input) {
	if input.OVN != nil {
		if !ovnTraceHasOutput(input.OVN.Trace) {
			builder.addFinding(Finding{
				Layer:   "ovn-trace",
				Status:  StatusFail,
				Message: "ovn-trace produced no output action",
			})
		}
	}
	if input.OVS != nil {
		actions := lastDatapathActions(input.OVS.Trace)
		switch {
		case actions == "":
			builder.addFinding(Finding{
				Layer:   "ovs-trace",
				Status:  StatusUnknown,
				Message: "ofproto/trace has no Datapath actions line",
			})
		case strings.Contains(strings.ToLower(actions), "drop"):
			builder.addFinding(Finding{
				Layer:   "ovs-trace",
				Status:  StatusFail,
				Message: "final OVS datapath action is drop",
			})
		}
		if !input.Neutron.Source.Endpoint.SameNetwork(
			input.Neutron.Destination.Endpoint,
		) && !strings.Contains(input.OVS.Flow, "dl_dst=") &&
			!probeDelivered(input) {
			builder.addFinding(Finding{
				Layer:  "ovs-trace",
				Status: StatusWarning,
				Message: "cross-network trace has no next-hop MAC; " +
					"it proves source egress but not the exact L2 path",
			})
		}
	}
}

func probeDelivered(input Input) bool {
	return input.ProbeError == nil &&
		input.Probe != nil &&
		input.Probe.Delivered
}

func ovnTraceHasOutput(trace string) bool {
	return strings.Contains(trace, "output;") ||
		strings.Contains(trace, "output to") ||
		strings.Contains(trace, "output(")
}

func lastDatapathActions(trace string) string {
	const marker = "Datapath actions:"
	index := strings.LastIndex(trace, marker)
	if index < 0 {
		return ""
	}
	line := trace[index+len(marker):]
	if newline := strings.IndexByte(line, '\n'); newline >= 0 {
		line = line[:newline]
	}
	return strings.TrimSpace(line)
}

func (builder *reportBuilder) addMTUFinding(path topology.NeutronPath) {
	sourceMTU := path.Source.Network.MTU
	destinationMTU := path.Destination.Network.MTU
	if sourceMTU > 0 && destinationMTU > 0 && sourceMTU != destinationMTU {
		builder.addFinding(Finding{
			Layer:  "mtu",
			Status: StatusWarning,
			Message: fmt.Sprintf(
				"network MTU differs: source=%d destination=%d",
				sourceMTU,
				destinationMTU,
			),
		})
	}
}

func (builder *reportBuilder) addNetworkFindings(
	path topology.NeutronPath,
) {
	for label, network := range map[string]topology.Network{
		"source-network":      path.Source.Network,
		"destination-network": path.Destination.Network,
	} {
		if network.Status != "" && network.Status != "ACTIVE" {
			builder.addFinding(Finding{
				Layer:  label,
				Status: StatusFail,
				Message: fmt.Sprintf(
					"Neutron network %s status=%s",
					network.ID,
					network.Status,
				),
			})
		}
	}
}
