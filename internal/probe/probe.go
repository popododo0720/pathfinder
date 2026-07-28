package probe

import (
	"context"
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
	if err := ValidatePath(neutronPath); err != nil {
		return topology.ProbeResult{}, err
	}

	packet, err := BuildPacket(neutronPath, microflow)
	if err != nil {
		return topology.ProbeResult{}, err
	}
	result := topology.ProbeResult{
		Method:          "ovs-ofctl packet-out + exact tap packet capture",
		Mode:            "live",
		Marker:          packet.Marker(),
		Protocol:        packet.Protocol,
		SourceIP:        packet.SourceIP.String(),
		DestinationIP:   packet.DestinationIP.String(),
		SourcePort:      packet.SourcePort,
		DestinationPort: packet.DestinationPort,
		SourceMAC:       packet.SourceMAC.String(),
		DestinationMAC:  packet.DestinationMAC.String(),
		ReplyExpected:   packet.ReplyExpected(),
		RequestFilter:   packet.RequestFilter(),
		ReplyFilter:     packet.ReplyFilter(),
		DetectionDescription: "delivery requires an exact BPF match " +
			"for the generated packet on the destination tap",
	}

	captureContext, cancelCaptures := context.WithCancel(ctx)
	defer cancelCaptures()
	requestCapture := startCapture(
		captureContext,
		destinationClient,
		ovsPath.Destination.Interface,
		result.RequestFilter,
		deliveryTimeout,
	)
	var replyCapture <-chan captureOutcome
	if result.ReplyExpected {
		replyCapture = startCapture(
			captureContext,
			sourceClient,
			ovsPath.Source.Interface,
			result.ReplyFilter,
			deliveryTimeout,
		)
	}
	warmup := time.NewTimer(captureWarmup)
	select {
	case <-ctx.Done():
		warmup.Stop()
		return result, ctx.Err()
	case <-warmup.C:
	}

	if err := sourceClient.InjectPacket(
		ctx,
		ovsPath.Source.OFPort,
		packet.Bytes,
	); err != nil {
		return result, fmt.Errorf("inject packet: %w", err)
	}
	result.Injected = true
	result.SourceObserved = true

	request, err := awaitCapture(ctx, requestCapture)
	if err != nil {
		result.Duration = time.Since(started)
		return result, fmt.Errorf(
			"observe generated packet at destination: %w",
			err,
		)
	}
	result.Delivered = !request.TimedOut
	result.RequestCapture = request.Output

	if replyCapture != nil {
		reply, err := awaitCapture(ctx, replyCapture)
		if err != nil {
			result.Duration = time.Since(started)
			return result, fmt.Errorf("observe reply at source: %w", err)
		}
		result.ReplyObserved = !reply.TimedOut
		result.ReplyCapture = reply.Output
	}
	result.Duration = time.Since(started)
	return result, nil
}

func startCapture(
	ctx context.Context,
	client *ovs.Client,
	interfaceName string,
	filter string,
	timeout time.Duration,
) <-chan captureOutcome {
	result := make(chan captureOutcome, 1)
	go func() {
		capture, err := client.CapturePacket(
			ctx,
			interfaceName,
			filter,
			timeout,
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
