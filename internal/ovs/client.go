package ovs

import (
	"context"
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
	source, err := sourceClient.GetEndpoint(
		ctx,
		neutronPath.Source.Endpoint.PortID,
	)
	if err != nil {
		return topology.OVSPath{}, fmt.Errorf(
			"source OVS endpoint: %w",
			err,
		)
	}

	destination, err := destinationClient.GetEndpoint(
		ctx,
		neutronPath.Destination.Endpoint.PortID,
	)
	if err != nil {
		return topology.OVSPath{}, fmt.Errorf(
			"destination OVS endpoint: %w",
			err,
		)
	}

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
	interfaceName, err := client.vsctl(
		ctx,
		"--bare",
		"--no-headings",
		"--columns=name",
		"find",
		"Interface",
		"external_ids:iface-id="+logicalPort,
	)
	if err != nil {
		return topology.OVSEndpoint{}, err
	}
	interfaceName = cleanOVSValue(firstLine(interfaceName))
	if interfaceName == "" {
		return topology.OVSEndpoint{}, fmt.Errorf(
			"%w for logical port %s on %s",
			ErrInterfaceNotFound,
			logicalPort,
			client.config.Host,
		)
	}

	ofportValue, err := client.vsctl(
		ctx,
		"--if-exists",
		"get",
		"Interface",
		interfaceName,
		"ofport",
	)
	if err != nil {
		return topology.OVSEndpoint{}, err
	}
	ofport, err := strconv.Atoi(cleanOVSValue(ofportValue))
	if err != nil {
		return topology.OVSEndpoint{}, fmt.Errorf(
			"parse ofport %q for %s: %w",
			ofportValue,
			interfaceName,
			err,
		)
	}

	linkState, err := client.vsctl(
		ctx,
		"--if-exists",
		"get",
		"Interface",
		interfaceName,
		"link_state",
	)
	if err != nil {
		return topology.OVSEndpoint{}, err
	}
	interfaceError, err := client.vsctl(
		ctx,
		"--if-exists",
		"get",
		"Interface",
		interfaceName,
		"error",
	)
	if err != nil {
		return topology.OVSEndpoint{}, err
	}

	return topology.OVSEndpoint{
		Host:        client.config.Host,
		Interface:   interfaceName,
		OFPort:      ofport,
		LinkState:   cleanOVSValue(linkState),
		Error:       cleanOVSValue(interfaceError),
		LogicalPort: logicalPort,
	}, nil
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
