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

var ipv4IDPattern = regexp.MustCompile(`\bid\s+([0-9]+)\b`)

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
	sourceRequest := startCapture(
		captureContext,
		sourceClient,
		ovsPath.Source.Interface,
		spec.requestFilter,
		timeout,
	)
	destinationRequest := startCapture(
		captureContext,
		destinationClient,
		ovsPath.Destination.Interface,
		spec.requestFilter,
		timeout,
	)
	var destinationReply <-chan captureOutcome
	var sourceReply <-chan captureOutcome
	if spec.replyExpected {
		destinationReply = startCapture(
			captureContext,
			destinationClient,
			ovsPath.Destination.Interface,
			spec.replyFilter,
			timeout,
		)
		sourceReply = startCapture(
			captureContext,
			sourceClient,
			ovsPath.Source.Interface,
			spec.replyFilter,
			timeout,
		)
	}

	result := topology.ProbeResult{
		Method:          "correlated source/destination tap packet capture",
		Mode:            "observe",
		Protocol:        spec.protocol,
		SourceIP:        spec.sourceIP,
		DestinationIP:   spec.destinationIP,
		SourcePort:      spec.sourcePort,
		DestinationPort: spec.destinationPort,
		SourceMAC:       neutronPath.Source.Endpoint.MACAddress,
		DestinationMAC:  neutronPath.Destination.Endpoint.MACAddress,
		ReplyExpected:   spec.replyExpected,
		RequestFilter:   spec.requestFilter,
		ReplyFilter:     spec.replyFilter,
		DetectionDescription: "existing traffic is correlated by " +
			"BPF filters and the IPv4 identification field",
	}

	sourceObservation, err := awaitCapture(ctx, sourceRequest)
	if err != nil {
		return result, fmt.Errorf("observe packet at source: %w", err)
	}
	result.SourceObserved = !sourceObservation.TimedOut
	result.SourceCapture = sourceObservation.Output
	if !result.SourceObserved {
		result.Duration = time.Since(started)
		return result, nil
	}

	destinationObservation, err := awaitCapture(
		ctx,
		destinationRequest,
	)
	if err != nil {
		return result, fmt.Errorf(
			"observe packet at destination: %w",
			err,
		)
	}
	result.RequestCapture = destinationObservation.Output
	result.Delivered = !destinationObservation.TimedOut &&
		capturesCorrelate(
			sourceObservation.Output,
			destinationObservation.Output,
		)
	result.Marker = captureMarker(sourceObservation.Output)

	if spec.replyExpected {
		generated, err := awaitCapture(ctx, destinationReply)
		if err != nil {
			return result, fmt.Errorf(
				"observe reply leaving destination: %w",
				err,
			)
		}
		result.ReplyGenerated = !generated.TimedOut
		result.ReplyGeneratedCapture = generated.Output

		returned, err := awaitCapture(ctx, sourceReply)
		if err != nil {
			return result, fmt.Errorf(
				"observe reply arriving at source: %w",
				err,
			)
		}
		result.ReplyCapture = returned.Output
		result.ReplyObserved = result.ReplyGenerated &&
			!returned.TimedOut &&
			capturesCorrelate(
				generated.Output,
				returned.Output,
			)
	}
	result.Duration = time.Since(started)
	return result, nil
}

func buildObservationSpec(
	path topology.NeutronPath,
	microflow string,
) (observationSpec, error) {
	sourceIP, destinationIP, err := compatibleIPv4(
		path.Source.Endpoint.FixedIPs,
		path.Destination.Endpoint.FixedIPs,
	)
	if err != nil {
		return observationSpec{}, err
	}
	protocol := parseProtocol(microflow)
	sourcePort := parsePort(sourcePortPattern, microflow)
	destinationPort := parsePort(
		destinationPortPattern,
		microflow,
	)
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
	firstMarker := captureMarker(first)
	secondMarker := captureMarker(second)
	if firstMarker == "" || secondMarker == "" {
		return strings.TrimSpace(first) != "" &&
			strings.TrimSpace(second) != ""
	}
	return firstMarker == secondMarker
}

func captureMarker(output string) string {
	matches := ipv4IDPattern.FindStringSubmatch(output)
	if len(matches) != 2 {
		return ""
	}
	return "ipv4-id:" + matches[1]
}
