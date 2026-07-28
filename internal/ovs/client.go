package ovs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"pathfinder/internal/execx"
	"pathfinder/internal/topology"
)

var ErrInterfaceNotFound = errors.New("OVS interface not found")

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

	flow, err := BuildTraceFlow(
		neutronPath.Source,
		neutronPath.Destination,
		source.OFPort,
		extraMicroflow,
	)
	if err != nil {
		return topology.OVSPath{}, err
	}

	trace, err := sourceClient.Trace(ctx, flow)
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
interface=$(run ovs-vsctl --bare --no-headings --columns=name find Interface external_ids:iface-id="$port" | head -n1)
ofport=
link_state=
interface_error=
if [ -n "$interface" ]; then
    ofport=$(run ovs-vsctl --if-exists get Interface "$interface" ofport | head -n1)
    link_state=$(run ovs-vsctl --if-exists get Interface "$interface" link_state | head -n1)
    interface_error=$(run ovs-vsctl --if-exists get Interface "$interface" error | head -n1)
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
) (string, error) {
	return client.run(
		ctx,
		"ovs-appctl",
		"ofproto/trace",
		client.config.Bridge,
		flow,
	)
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

func (client *Client) TXPackets(
	ctx context.Context,
	interfaceName string,
) (uint64, error) {
	value, err := client.vsctl(
		ctx,
		"--if-exists",
		"get",
		"Interface",
		interfaceName,
		"statistics:tx_packets",
	)
	if err != nil {
		return 0, err
	}
	value = cleanOVSValue(value)
	counter, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"parse tx_packets %q for %s: %w",
			value,
			interfaceName,
			err,
		)
	}
	return counter, nil
}

func (client *Client) vsctl(
	ctx context.Context,
	args ...string,
) (string, error) {
	return client.run(ctx, "ovs-vsctl", args...)
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
