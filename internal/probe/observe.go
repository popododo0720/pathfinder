package probe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"pathfinder/internal/ovs"
	"pathfinder/internal/topology"
)

var (
	ipv4IDPattern   = regexp.MustCompile(`\bid\s+([0-9]+)\b`)
	icmpEchoPattern = regexp.MustCompile(
		`(?i)\bICMP echo (?:request|reply), id ([0-9]+), seq ([0-9]+)\b`,
	)
	tcpSequencePattern = regexp.MustCompile(
		`(?i)\bFlags \[[^]]+\].*\bseq ([0-9]+)(?::[0-9]+)?\b`,
	)
)

const observationCaptureLimit = 64

type observationSpec struct {
	protocol        string
	sourceIP        string
	destinationIP   string
	sourcePort      int
	destinationPort int
	requestFilter   string
	replyFilter     string
	replyExpected   bool
}

func Observe(
	ctx context.Context,
	sourceClient *ovs.Client,
	destinationClient *ovs.Client,
	neutronPath topology.NeutronPath,
	ovsPath topology.OVSPath,
	microflow string,
	timeout time.Duration,
) (topology.ProbeResult, error) {
	started := time.Now()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := ValidatePath(neutronPath); err != nil {
		return topology.ProbeResult{}, err
	}
	spec, err := buildObservationSpec(neutronPath, microflow)
	if err != nil {
		return topology.ProbeResult{}, err
	}

	captureContext, cancelCaptures := context.WithCancel(ctx)
	defer cancelCaptures()
	sourceRequest := startCaptureCount(
		captureContext,
		sourceClient,
		ovsPath.Source.Interface,
		spec.requestFilter,
		timeout,
		observationCaptureLimit,
	)
	destinationRequest := startCaptureCount(
		captureContext,
		destinationClient,
		ovsPath.Destination.Interface,
		spec.requestFilter,
		timeout,
		observationCaptureLimit,
	)
	var destinationReply <-chan captureOutcome
	var sourceReply <-chan captureOutcome
	if spec.replyExpected {
		destinationReply = startCaptureCount(
			captureContext,
			destinationClient,
			ovsPath.Destination.Interface,
			spec.replyFilter,
			timeout,
			observationCaptureLimit,
		)
		sourceReply = startCaptureCount(
			captureContext,
			sourceClient,
			ovsPath.Source.Interface,
			spec.replyFilter,
			timeout,
			observationCaptureLimit,
		)
	}

	result := topology.ProbeResult{
		Method:                     "correlated source/destination tap packet capture",
		Mode:                       "observe",
		Protocol:                   spec.protocol,
		SourceIP:                   spec.sourceIP,
		DestinationIP:              spec.destinationIP,
		SourcePort:                 spec.sourcePort,
		DestinationPort:            spec.destinationPort,
		SourceMAC:                  neutronPath.Source.Endpoint.MACAddress,
		DestinationMAC:             neutronPath.Destination.Endpoint.MACAddress,
		SourceObservationAttempted: true,
		ReplyExpected:              spec.replyExpected,
		RequestFilter:              spec.requestFilter,
		ReplyFilter:                spec.replyFilter,
		DetectionDescription: "existing traffic is correlated by " +
			"BPF filters, the IPv4 identification field, and ICMP/TCP " +
			"packet markers when available",
	}

	sourceObservation, err := awaitCapture(ctx, sourceRequest)
	if err != nil {
		result.FailureStage = topology.ProbeFailureSourceCapture
		result.Duration = time.Since(started)
		return result, fmt.Errorf("observe packet at source: %w", err)
	}
	result.SourceObserved = strings.TrimSpace(sourceObservation.Output) != ""
	result.SourceCapture = sourceObservation.Output

	destinationObservation, err := awaitCapture(
		ctx,
		destinationRequest,
	)
	if err != nil {
		result.FailureStage = topology.ProbeFailureDeliveryCapture
		result.Duration = time.Since(started)
		return result, fmt.Errorf(
			"observe packet at destination: %w",
			err,
		)
	}
	result.RequestCapture = destinationObservation.Output
	result.Marker = correlatedMarker(
		sourceObservation.Output,
		destinationObservation.Output,
	)
	result.Delivered = result.SourceObserved && result.Marker != ""

	if spec.replyExpected && result.Delivered {
		result.ReplyGenerationAttempted = true
		generated, err := awaitCapture(ctx, destinationReply)
		if err != nil {
			result.FailureStage = topology.ProbeFailureReplyGeneration
			result.Duration = time.Since(started)
			return result, fmt.Errorf(
				"observe reply leaving destination: %w",
				err,
			)
		}
		result.ReplyGenerated = strings.TrimSpace(generated.Output) != ""
		result.ReplyGeneratedCapture = generated.Output

		if !result.ReplyGenerated {
			result.Duration = time.Since(started)
			return result, nil
		}
		result.ReplyObservationAttempted = true
		returned, err := awaitCapture(ctx, sourceReply)
		if err != nil {
			result.FailureStage = topology.ProbeFailureReturnCapture
			result.Duration = time.Since(started)
			return result, fmt.Errorf(
				"observe reply arriving at source: %w",
				err,
			)
		}
		result.ReplyCapture = returned.Output
		result.ReplyObserved = correlatedMarker(
			generated.Output,
			returned.Output,
		) != ""
	}
	result.Duration = time.Since(started)
	return result, nil
}

func buildObservationSpec(
	path topology.NeutronPath,
	microflow string,
) (observationSpec, error) {
	sourceIP, destinationIP, err := compatibleIPv4(
		path.Source.FlowFixedIPs(),
		path.Destination.FlowFixedIPs(),
	)
	if err != nil {
		return observationSpec{}, err
	}
	flow, err := parseProbeMicroflow(microflow)
	if err != nil {
		return observationSpec{}, err
	}
	protocol := flow.protocol
	sourcePort := flow.sourcePort
	destinationPort := flow.destinationPort
	base := fmt.Sprintf(
		"src host %s and dst host %s",
		sourceIP,
		destinationIP,
	)
	reverse := fmt.Sprintf(
		"src host %s and dst host %s",
		destinationIP,
		sourceIP,
	)
	switch protocol {
	case "tcp", "udp":
		base += " and " + protocol
		reverse += " and " + protocol
		if sourcePort > 0 {
			base += fmt.Sprintf(" src port %d", sourcePort)
			reverse += fmt.Sprintf(" dst port %d", sourcePort)
		}
		if destinationPort > 0 {
			base += fmt.Sprintf(" dst port %d", destinationPort)
			reverse += fmt.Sprintf(" src port %d", destinationPort)
		}
	case "icmp":
		base += " and icmp and icmp[0] = 8"
		reverse += " and icmp and icmp[0] = 0"
	}
	return observationSpec{
		protocol:        protocol,
		sourceIP:        sourceIP.String(),
		destinationIP:   destinationIP.String(),
		sourcePort:      sourcePort,
		destinationPort: destinationPort,
		requestFilter:   base,
		replyFilter:     reverse,
		replyExpected:   protocol == "icmp" || protocol == "tcp",
	}, nil
}

func capturesCorrelate(first string, second string) bool {
	return correlatedMarker(first, second) != ""
}

func correlatedMarker(first string, second string) string {
	firstMarkers := captureMarkers(first)
	if len(firstMarkers) == 0 {
		return ""
	}
	for marker := range captureMarkers(second) {
		if _, found := firstMarkers[marker]; found {
			return marker
		}
	}
	return ""
}

func captureMarkers(output string) map[string]struct{} {
	result := make(map[string]struct{})
	for line := range strings.SplitSeq(output, "\n") {
		ipv4 := ipv4IDPattern.FindStringSubmatch(line)
		if len(ipv4) != 2 {
			continue
		}
		marker := "ipv4-id:" + ipv4[1]
		if icmp := icmpEchoPattern.FindStringSubmatch(line); len(icmp) == 3 {
			marker += ",icmp-id:" + icmp[1] + ",icmp-seq:" + icmp[2]
		} else if tcp := tcpSequencePattern.FindStringSubmatch(
			line,
		); len(tcp) == 2 {
			marker += ",tcp-seq:" + tcp[1]
		}
		result[marker] = struct{}{}
	}
	return result
}

func captureMarker(output string) string {
	for marker := range captureMarkers(output) {
		return marker
	}
	return ""
}
