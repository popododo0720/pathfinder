package ovs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"pathfinder/internal/execx"
	"pathfinder/internal/topology"
)

var ErrInterfaceNotFound = errors.New("OVS interface not found")

type CaptureResult struct {
	Output   string
	TimedOut bool
}

type Config struct {
	Host            string
	ContainerEngine string
	Container       string
	Bridge          string
}

type Client struct {
	runner execx.Runner
	config Config
}

func NewClient(runner execx.Runner, config Config) *Client {
	if config.ContainerEngine == "" {
		config.ContainerEngine = "docker"
	}
	if config.Container == "" {
		config.Container = "openvswitch_vswitchd"
	}
	if config.Bridge == "" {
		config.Bridge = "br-int"
	}
	return &Client{runner: runner, config: config}
}

func DiscoverPath(
	ctx context.Context,
	sourceClient *Client,
	destinationClient *Client,
	neutronPath topology.NeutronPath,
	extraMicroflow string,
	connectionStates []string,
) (topology.OVSPath, error) {
	type endpointResult struct {
		endpoint topology.OVSEndpoint
		err      error
	}
	sourceResult := make(chan endpointResult, 1)
	destinationResult := make(chan endpointResult, 1)
	go func() {
		endpoint, err := sourceClient.GetEndpoint(
			ctx,
			neutronPath.Source.Endpoint.PortID,
		)
		sourceResult <- endpointResult{endpoint: endpoint, err: err}
	}()
	go func() {
		endpoint, err := destinationClient.GetEndpoint(
			ctx,
			neutronPath.Destination.Endpoint.PortID,
		)
		destinationResult <- endpointResult{
			endpoint: endpoint,
			err:      err,
		}
	}()

	sourceObservation := <-sourceResult
	destinationObservation := <-destinationResult
	if sourceObservation.err != nil {
		return topology.OVSPath{}, fmt.Errorf(
			"source OVS endpoint: %w",
			sourceObservation.err,
		)
	}
	if destinationObservation.err != nil {
		return topology.OVSPath{}, fmt.Errorf(
			"destination OVS endpoint: %w",
			destinationObservation.err,
		)
	}
	source := sourceObservation.endpoint
	destination := destinationObservation.endpoint

	knownNextHopMAC := ""
	if nextHop, found := topology.KnownRouterNextHop(
		neutronPath,
	); found {
		knownNextHopMAC = nextHop.MACAddress
	}
	flow, err := BuildTraceFlowWithNextHop(
		neutronPath.Source,
		neutronPath.Destination,
		source.OFPort,
		extraMicroflow,
		knownNextHopMAC,
	)
	if err != nil {
		return topology.OVSPath{}, err
	}

	trace, err := sourceClient.Trace(ctx, flow, connectionStates)
	if err != nil {
		return topology.OVSPath{}, err
	}

	return topology.OVSPath{
		Source:      source,
		Destination: destination,
		Flow:        flow,
		Trace:       trace,
	}, nil
}

func (client *Client) GetEndpoint(
	ctx context.Context,
	logicalPort string,
) (topology.OVSEndpoint, error) {
	snapshot, err := client.endpointSnapshot(ctx, logicalPort)
	if err != nil {
		return topology.OVSEndpoint{}, err
	}
	interfaceName := cleanOVSValue(snapshot["interface"])
	if interfaceName == "" {
		return topology.OVSEndpoint{}, fmt.Errorf(
			"%w for logical port %s on %s",
			ErrInterfaceNotFound,
			logicalPort,
			client.config.Host,
		)
	}

	ofportValue := snapshot["ofport"]
	ofport, err := strconv.Atoi(cleanOVSValue(ofportValue))
	if err != nil {
		return topology.OVSEndpoint{}, fmt.Errorf(
			"parse ofport %q for %s: %w",
			ofportValue,
			interfaceName,
			err,
		)
	}

	return topology.OVSEndpoint{
		Host:        client.config.Host,
		Interface:   interfaceName,
		OFPort:      ofport,
		LinkState:   cleanOVSValue(snapshot["link_state"]),
		Error:       cleanOVSValue(snapshot["error"]),
		LogicalPort: logicalPort,
	}, nil
}

func (client *Client) endpointSnapshot(
	ctx context.Context,
	logicalPort string,
) (map[string]string, error) {
	const script = `set -eu
engine=$1
container=$2
port=$3
run() { "$engine" exec "$container" "$@"; }
interface=$(run ovs-vsctl --bare --no-headings --columns=name find Interface external_ids:iface-id="$port")
ofport=
link_state=
interface_error=
if [ -n "$interface" ]; then
    ofport=$(run ovs-vsctl --if-exists get Interface "$interface" ofport)
    link_state=$(run ovs-vsctl --if-exists get Interface "$interface" link_state)
    interface_error=$(run ovs-vsctl --if-exists get Interface "$interface" error)
fi
printf 'interface=%s\nofport=%s\nlink_state=%s\nerror=%s\n' \
    "$interface" "$ofport" "$link_state" "$interface_error"`

	result, err := client.runner.Run(
		ctx,
		client.config.Host,
		"sh",
		"-c",
		script,
		"pathfinder-ovs-snapshot",
		client.config.ContainerEngine,
		client.config.Container,
		logicalPort,
	)
	if err != nil {
		return nil, fmt.Errorf("OVS endpoint snapshot: %w", err)
	}
	return parseSnapshot(result.Stdout), nil
}

func (client *Client) Trace(
	ctx context.Context,
	flow string,
	connectionStates []string,
) (string, error) {
	args := make([]string, 0, len(connectionStates)*2+3)
	args = append(args, "ofproto/trace")
	for _, state := range connectionStates {
		args = append(args, "--ct-next", state)
	}
	args = append(args, client.config.Bridge, flow)
	return client.run(ctx, "ovs-appctl", args...)
}

func (client *Client) InjectPacket(
	ctx context.Context,
	sourceOFPort int,
	packet []byte,
) error {
	_, err := client.run(
		ctx,
		"ovs-ofctl",
		"packet-out",
		client.config.Bridge,
		strconv.Itoa(sourceOFPort),
		"resubmit(,0)",
		hex.EncodeToString(packet),
	)
	return err
}

func (client *Client) CapturePacket(
	ctx context.Context,
	interfaceName string,
	filter string,
	timeout time.Duration,
) (CaptureResult, error) {
	return client.CapturePackets(ctx, interfaceName, filter, timeout, 1)
}

func (client *Client) CapturePackets(
	ctx context.Context,
	interfaceName string,
	filter string,
	timeout time.Duration,
	maxPackets int,
) (CaptureResult, error) {
	if timeout <= 0 {
		timeout = time.Second
	}
	if maxPackets <= 0 {
		maxPackets = 1
	}
	result, err := client.runner.Run(
		ctx,
		client.config.Host,
		"timeout",
		"--signal=INT",
		timeout.String(),
		"tcpdump",
		"-i",
		interfaceName,
		"-nne",
		"-vv",
		"-l",
		"-c",
		strconv.Itoa(maxPackets),
		filter,
	)
	if err != nil {
		var commandError *execx.CommandError
		if errors.As(err, &commandError) &&
			commandError.ExitCode == 124 {
			return CaptureResult{
				Output:   strings.TrimSpace(result.Stdout),
				TimedOut: true,
			}, nil
		}
		return CaptureResult{}, fmt.Errorf(
			"capture on %s: %w",
			interfaceName,
			err,
		)
	}
	return CaptureResult{
		Output: strings.TrimSpace(result.Stdout),
	}, nil
}

func (client *Client) run(
	ctx context.Context,
	tool string,
	args ...string,
) (string, error) {
	commandName := tool
	commandArgs := args
	if client.config.Container != "" {
		commandName = client.config.ContainerEngine
		commandArgs = append(
			[]string{"exec", client.config.Container, tool},
			args...,
		)
	}

	result, err := client.runner.Run(
		ctx,
		client.config.Host,
		commandName,
		commandArgs...,
	)
	if err != nil {
		return "", fmt.Errorf("%s: %w", tool, err)
	}
	return strings.TrimSpace(result.Stdout), nil
}

func cleanOVSValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "[]" || value == "{}" {
		return ""
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}

func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index]
	}
	return value
}

func parseSnapshot(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			result[key] = value
		}
	}
	return result
}
