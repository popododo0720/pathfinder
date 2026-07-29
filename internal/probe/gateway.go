package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"pathfinder/internal/ovs"
	"pathfinder/internal/topology"
)

var ErrNextHopResolution = errors.New("resolve next-hop MAC")

var arpReplyMACPattern = regexp.MustCompile(
	`(?i)\bis-at\s+([0-9a-f:]{17})\b`,
)

type NextHop struct {
	IP     string
	MAC    string
	Source string
}

func ResolveNextHop(
	ctx context.Context,
	sourceClient *ovs.Client,
	path topology.NeutronPath,
	ovsPath topology.OVSPath,
	timeout time.Duration,
) (NextHop, error) {
	subnetID, sourceIP, gatewayIP, err := sourceGateway(path.Source)
	if err != nil {
		return NextHop{}, err
	}
	for _, router := range path.Routers {
		for _, routerInterface := range router.Interfaces {
			if routerInterface.SubnetID == subnetID &&
				routerInterface.IPAddress == gatewayIP.String() &&
				routerInterface.MACAddress != "" {
				return NextHop{
					IP:     routerInterface.IPAddress,
					MAC:    routerInterface.MACAddress,
					Source: "Neutron router interface",
				}, nil
			}
		}
	}

	filter := fmt.Sprintf(
		"arp and arp[6:2] = 2 and src host %s and dst host %s",
		gatewayIP,
		sourceIP,
	)
	captureContext, cancelCapture := context.WithCancel(ctx)
	defer cancelCapture()
	capture := startCapture(
		captureContext,
		sourceClient,
		ovsPath.Source.Interface,
		filter,
		captureTimeoutAfterWarmup(timeout),
	)
	if err := waitCaptureWarmup(ctx); err != nil {
		return NextHop{}, err
	}
	frame, err := buildARPRequest(
		path.Source.Endpoint.MACAddress,
		sourceIP,
		gatewayIP,
	)
	if err != nil {
		return NextHop{}, err
	}
	if err := sourceClient.InjectPacket(
		ctx,
		ovsPath.Source.OFPort,
		frame,
	); err != nil {
		return NextHop{}, fmt.Errorf(
			"%w: inject ARP request: %v",
			ErrNextHopResolution,
			err,
		)
	}
	observation, err := awaitCapture(ctx, capture)
	if err != nil {
		return NextHop{}, fmt.Errorf(
			"%w: capture ARP reply: %v",
			ErrNextHopResolution,
			err,
		)
	}
	if observation.TimedOut {
		return NextHop{}, fmt.Errorf(
			"%w: no ARP reply from gateway %s",
			ErrNextHopResolution,
			gatewayIP,
		)
	}
	matches := arpReplyMACPattern.FindStringSubmatch(
		observation.Output,
	)
	if len(matches) != 2 {
		return NextHop{}, fmt.Errorf(
			"%w: could not parse gateway MAC from packet capture",
			ErrNextHopResolution,
		)
	}
	return NextHop{
		IP:     gatewayIP.String(),
		MAC:    strings.ToLower(matches[1]),
		Source: "ARP reply through source OVS port",
	}, nil
}

func sourceGateway(
	source topology.EndpointContext,
) (string, netip.Addr, netip.Addr, error) {
	for _, fixedIP := range source.FlowFixedIPs() {
		address, err := netip.ParseAddr(fixedIP.Address)
		if err != nil || !address.Is4() {
			continue
		}
		for _, subnet := range source.Subnets {
			if subnet.ID != fixedIP.SubnetID ||
				subnet.GatewayIP == "" {
				continue
			}
			gateway, err := netip.ParseAddr(subnet.GatewayIP)
			if err == nil && gateway.Is4() {
				return subnet.ID, address, gateway, nil
			}
		}
	}
	return "", netip.Addr{}, netip.Addr{}, fmt.Errorf(
		"%w: source port has no IPv4 subnet gateway",
		ErrNextHopResolution,
	)
}

func buildARPRequest(
	sourceMACValue string,
	sourceIP netip.Addr,
	targetIP netip.Addr,
) ([]byte, error) {
	sourceMAC, err := net.ParseMAC(sourceMACValue)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: parse source MAC: %v",
			ErrNextHopResolution,
			err,
		)
	}
	if !sourceIP.Is4() || !targetIP.Is4() {
		return nil, fmt.Errorf(
			"%w: ARP requires IPv4 addresses",
			ErrNextHopResolution,
		)
	}

	frame := make([]byte, 42)
	for index := 0; index < 6; index++ {
		frame[index] = 0xff
	}
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	copy(frame[22:28], sourceMAC)
	copy(frame[28:32], sourceIP.AsSlice())
	copy(frame[38:42], targetIP.AsSlice())
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame, nil
}

func waitCaptureWarmup(ctx context.Context) error {
	timer := time.NewTimer(captureWarmup)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
