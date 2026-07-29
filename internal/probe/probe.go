package probe

import (
	"context"
	"errors"
	"fmt"
	"time"

	"pathfinder/internal/ovs"
	"pathfinder/internal/topology"
)

const defaultDeliveryTimeout = time.Second
const captureWarmup = 250 * time.Millisecond

type captureOutcome struct {
	result ovs.CaptureResult
	err    error
}

func Run(
	ctx context.Context,
	sourceClient *ovs.Client,
	destinationClient *ovs.Client,
	neutronPath topology.NeutronPath,
	ovsPath topology.OVSPath,
	microflow string,
	deliveryTimeout time.Duration,
) (topology.ProbeResult, error) {
	started := time.Now()
	if deliveryTimeout <= 0 {
		deliveryTimeout = defaultDeliveryTimeout
	}
	captureTimeout := captureTimeoutAfterWarmup(deliveryTimeout)
	if err := ValidatePath(neutronPath); err != nil {
		return topology.ProbeResult{}, err
	}

	nextHop := NextHop{}
	packet, err := BuildPacket(neutronPath, microflow)
	if errors.Is(err, ErrNextHopMACRequired) {
		nextHop, err = ResolveNextHop(
			ctx,
			sourceClient,
			neutronPath,
			ovsPath,
			deliveryTimeout,
		)
		if err == nil {
			packet, err = BuildPacketWithDestinationMAC(
				neutronPath,
				microflow,
				nextHop.MAC,
			)
		}
	} else if err == nil &&
		topology.RequiresNextHop(
			neutronPath.Source,
			neutronPath.Destination,
			packet.SourceIP,
			packet.DestinationIP,
		) {
		_, _, nextHopIP, routeSource, nextHopErr := sourceNextHop(
			neutronPath.Source,
			packet.DestinationIP,
		)
		if nextHopErr == nil {
			nextHop.IP = nextHopIP.String()
			nextHop.Source = routeSource + "; MAC from microflow eth.dst"
		} else {
			nextHop.Source = "microflow eth.dst"
		}
		nextHop.MAC = packet.DestinationMAC.String()
	}
	if err != nil {
		return topology.ProbeResult{}, err
	}
	result := topology.ProbeResult{
		Method:           "ovs-ofctl packet-out + exact tap packet capture",
		Mode:             "live",
		Marker:           packet.Marker(),
		Protocol:         packet.Protocol,
		SourceIP:         packet.SourceIP.String(),
		DestinationIP:    packet.DestinationIP.String(),
		SourcePort:       packet.SourcePort,
		DestinationPort:  packet.DestinationPort,
		SourceMAC:        packet.SourceMAC.String(),
		DestinationMAC:   packet.DestinationMAC.String(),
		NextHopIP:        nextHop.IP,
		NextHopMACSource: nextHop.Source,
		ReplyExpected:    packet.ReplyExpected(),
		RequestFilter:    packet.RequestFilter(),
		ReplyFilter:      packet.ReplyFilter(),
		DetectionDescription: "packet-out acceptance proves injection into " +
			"source OVS; source tap capture is not attempted; delivery " +
			"requires an exact BPF match on the destination tap",
	}

	captureContext, cancelCaptures := context.WithCancel(ctx)
	defer cancelCaptures()
	requestCapture := startCapture(
		captureContext,
		destinationClient,
		ovsPath.Destination.Interface,
		result.RequestFilter,
		captureTimeout,
	)
	var replyCapture <-chan captureOutcome
	var replyGeneratedCapture <-chan captureOutcome
	if result.ReplyExpected {
		replyCapture = startCapture(
			captureContext,
			sourceClient,
			ovsPath.Source.Interface,
			result.ReplyFilter,
			captureTimeout,
		)
		replyGeneratedCapture = startCapture(
			captureContext,
			destinationClient,
			ovsPath.Destination.Interface,
			result.ReplyFilter,
			captureTimeout,
		)
	}
	warmup := time.NewTimer(captureWarmup)
	select {
	case <-ctx.Done():
		warmup.Stop()
		result.FailureStage = topology.ProbeFailureCaptureWarmup
		result.Duration = time.Since(started)
		return result, ctx.Err()
	case <-warmup.C:
	}

	if err := sourceClient.InjectPacket(
		ctx,
		ovsPath.Source.OFPort,
		packet.Bytes,
	); err != nil {
		result.FailureStage = topology.ProbeFailureInjection
		result.Duration = time.Since(started)
		return result, fmt.Errorf("inject packet: %w", err)
	}
	result.Injected = true

	request, err := awaitCapture(ctx, requestCapture)
	if err != nil {
		result.FailureStage = topology.ProbeFailureDeliveryCapture
		result.Duration = time.Since(started)
		return result, fmt.Errorf(
			"observe generated packet at destination: %w",
			err,
		)
	}
	result.Delivered = !request.TimedOut
	result.RequestCapture = request.Output

	if replyCapture != nil {
		if !result.Delivered {
			result.Duration = time.Since(started)
			return result, nil
		}
		result.ReplyGenerationAttempted = true
		generatedReply, err := awaitCapture(
			ctx,
			replyGeneratedCapture,
		)
		if err != nil {
			result.FailureStage = topology.ProbeFailureReplyGeneration
			result.Duration = time.Since(started)
			return result, fmt.Errorf(
				"observe reply leaving destination: %w",
				err,
			)
		}
		result.ReplyGenerated = !generatedReply.TimedOut
		result.ReplyGeneratedCapture = generatedReply.Output

		if !result.ReplyGenerated {
			result.Duration = time.Since(started)
			return result, nil
		}
		result.ReplyObservationAttempted = true
		reply, err := awaitCapture(ctx, replyCapture)
		if err != nil {
			result.FailureStage = topology.ProbeFailureReturnCapture
			result.Duration = time.Since(started)
			return result, fmt.Errorf("observe reply at source: %w", err)
		}
		result.ReplyObserved = !reply.TimedOut
		result.ReplyCapture = reply.Output
	}
	result.Duration = time.Since(started)
	return result, nil
}

func captureTimeoutAfterWarmup(observationTimeout time.Duration) time.Duration {
	if observationTimeout <= 0 {
		observationTimeout = defaultDeliveryTimeout
	}
	return observationTimeout + captureWarmup
}

func startCapture(
	ctx context.Context,
	client *ovs.Client,
	interfaceName string,
	filter string,
	timeout time.Duration,
) <-chan captureOutcome {
	return startCaptureCount(ctx, client, interfaceName, filter, timeout, 1)
}

func startCaptureCount(
	ctx context.Context,
	client *ovs.Client,
	interfaceName string,
	filter string,
	timeout time.Duration,
	maxPackets int,
) <-chan captureOutcome {
	result := make(chan captureOutcome, 1)
	go func() {
		capture, err := client.CapturePackets(
			ctx,
			interfaceName,
			filter,
			timeout,
			maxPackets,
		)
		result <- captureOutcome{result: capture, err: err}
	}()
	return result
}

func awaitCapture(
	ctx context.Context,
	result <-chan captureOutcome,
) (ovs.CaptureResult, error) {
	select {
	case <-ctx.Done():
		return ovs.CaptureResult{}, ctx.Err()
	case outcome := <-result:
		return outcome.result, outcome.err
	}
}
