package ovn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"pathfinder/internal/execx"
	"pathfinder/internal/topology"
)

var ErrLogicalPortNotFound = errors.New("OVN logical port not found")

type Config struct {
	Host            string
	ContainerEngine string
	Container       string
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
		config.Container = "ovn_northd"
	}

	return &Client{
		runner: runner,
		config: config,
	}
}

func (client *Client) DiscoverPath(
	ctx context.Context,
	neutronPath topology.NeutronPath,
	extraMicroflow string,
	connectionStates []string,
	minimal bool,
) (topology.OVNPath, error) {
	source, err := client.GetEndpoint(
		ctx,
		neutronPath.Source.Endpoint.PortID,
	)
	if err != nil {
		return topology.OVNPath{}, fmt.Errorf(
			"source OVN endpoint: %w",
			err,
		)
	}

	destination, err := client.GetEndpoint(
		ctx,
		neutronPath.Destination.Endpoint.PortID,
	)
	if err != nil {
		return topology.OVNPath{}, fmt.Errorf(
			"destination OVN endpoint: %w",
			err,
		)
	}

	microflow, err := BuildMicroflow(
		neutronPath.Source,
		neutronPath.Destination,
		extraMicroflow,
	)
	if err != nil {
		return topology.OVNPath{}, err
	}

	trace, err := client.Trace(
		ctx,
		source.LogicalSwitch,
		microflow,
		connectionStates,
		minimal,
	)
	if err != nil {
		return topology.OVNPath{}, err
	}

	return topology.OVNPath{
		Source:      source,
		Destination: destination,
		Microflow:   microflow,
		Trace:       trace,
	}, nil
}

func (client *Client) GetEndpoint(
	ctx context.Context,
	logicalPort string,
) (topology.OVNEndpoint, error) {
	logicalPortUUID, err := client.nbctl(
		ctx,
		"--if-exists",
		"get",
		"Logical_Switch_Port",
		logicalPort,
		"_uuid",
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}
	if logicalPortUUID == "" {
		return topology.OVNEndpoint{}, fmt.Errorf(
			"%w: %s",
			ErrLogicalPortNotFound,
			logicalPort,
		)
	}

	logicalSwitch, err := client.nbctl(
		ctx,
		"lsp-get-ls",
		logicalPort,
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}

	portBindingUUID, err := client.sbctl(
		ctx,
		"--bare",
		"--no-headings",
		"--columns=_uuid",
		"find",
		"Port_Binding",
		"logical_port="+logicalPort,
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}

	endpoint := topology.OVNEndpoint{
		LogicalPort:     logicalPort,
		LogicalPortUUID: cleanOVSValue(logicalPortUUID),
		LogicalSwitch:   cleanOVSValue(logicalSwitch),
		PortBindingUUID: cleanOVSValue(firstLine(portBindingUUID)),
	}
	if endpoint.PortBindingUUID == "" {
		return endpoint, nil
	}

	endpoint.DatapathUUID, err = client.sbGet(
		ctx,
		"Port_Binding",
		endpoint.PortBindingUUID,
		"datapath",
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}
	endpoint.ChassisUUID, err = client.sbGet(
		ctx,
		"Port_Binding",
		endpoint.PortBindingUUID,
		"chassis",
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}

	up, err := client.sbGet(
		ctx,
		"Port_Binding",
		endpoint.PortBindingUUID,
		"up",
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}
	endpoint.Up, _ = strconv.ParseBool(up)

	tunnelKey, err := client.sbGet(
		ctx,
		"Port_Binding",
		endpoint.PortBindingUUID,
		"tunnel_key",
	)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}
	endpoint.PortBindingTunnel, _ = strconv.Atoi(tunnelKey)

	if endpoint.ChassisUUID != "" {
		endpoint.ChassisName, err = client.sbGet(
			ctx,
			"Chassis",
			endpoint.ChassisUUID,
			"name",
		)
		if err != nil {
			return topology.OVNEndpoint{}, err
		}
	}

	return endpoint, nil
}

func (client *Client) Trace(
	ctx context.Context,
	datapath string,
	microflow string,
	connectionStates []string,
	minimal bool,
) (string, error) {
	args := make([]string, 0, len(connectionStates)*2+4)
	if minimal {
		args = append(args, "--minimal")
	}
	for _, state := range connectionStates {
		args = append(args, "--ct", state)
	}
	args = append(args, datapath, microflow)

	return client.run(ctx, "ovn-trace", args...)
}

func (client *Client) sbGet(
	ctx context.Context,
	table string,
	record string,
	column string,
) (string, error) {
	value, err := client.sbctl(
		ctx,
		"--if-exists",
		"get",
		table,
		record,
		column,
	)
	if err != nil {
		return "", err
	}
	return cleanOVSValue(value), nil
}

func (client *Client) nbctl(
	ctx context.Context,
	args ...string,
) (string, error) {
	return client.run(ctx, "ovn-nbctl", args...)
}

func (client *Client) sbctl(
	ctx context.Context,
	args ...string,
) (string, error) {
	return client.run(ctx, "ovn-sbctl", args...)
}

func (client *Client) run(
	ctx context.Context,
	tool string,
	args ...string,
) (string, error) {
	commandArgs := args
	commandName := tool

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
