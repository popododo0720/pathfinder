package probe

import (
	"context"
	"fmt"
	"time"

	"pathfinder/internal/ovs"
	"pathfinder/internal/topology"
)

const defaultDeliveryTimeout = time.Second

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
	before, err := destinationClient.TXPackets(
		ctx,
		ovsPath.Destination.Interface,
	)
	if err != nil {
		return topology.ProbeResult{}, fmt.Errorf(
			"read destination tx_packets before injection: %w",
			err,
		)
	}

	result := topology.ProbeResult{
		Method:              "ovs-ofctl packet-out + destination tap tx_packets",
		Protocol:            packet.Protocol,
		SourceIP:            packet.SourceIP.String(),
		DestinationIP:       packet.DestinationIP.String(),
		SourcePort:          packet.SourcePort,
		DestinationPort:     packet.DestinationPort,
		SourceMAC:           packet.SourceMAC.String(),
		DestinationMAC:      packet.DestinationMAC.String(),
		DestinationTXBefore: before,
		DetectionDescription: "delivery means the destination OVS " +
			"interface tx_packets counter increased",
	}

	if err := sourceClient.InjectPacket(
		ctx,
		ovsPath.Source.OFPort,
		packet.Bytes,
	); err != nil {
		return result, fmt.Errorf("inject packet: %w", err)
	}
	result.Injected = true

	timer := time.NewTimer(deliveryTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	result.DestinationTXAfter = before
	for {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(started)
			return result, ctx.Err()
		case <-timer.C:
			result.Duration = time.Since(started)
			return result, nil
		case <-ticker.C:
			after, err := destinationClient.TXPackets(
				ctx,
				ovsPath.Destination.Interface,
			)
			if err != nil {
				result.Duration = time.Since(started)
				return result, fmt.Errorf(
					"read destination tx_packets after injection: %w",
					err,
				)
			}
			result.DestinationTXAfter = after
			if after > before {
				result.DestinationTXDelta = after - before
				result.Delivered = true
				result.Duration = time.Since(started)
				return result, nil
			}
		}
	}
}
