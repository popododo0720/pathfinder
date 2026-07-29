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
	type endpointResult struct {
		endpoint topology.OVNEndpoint
		err      error
	}
	sourceResult := make(chan endpointResult, 1)
	destinationResult := make(chan endpointResult, 1)
	go func() {
		endpoint, err := client.GetEndpoint(
			ctx,
			neutronPath.Source.Endpoint.PortID,
		)
		sourceResult <- endpointResult{endpoint: endpoint, err: err}
	}()
	go func() {
		endpoint, err := client.GetEndpoint(
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
		return topology.OVNPath{}, fmt.Errorf(
			"source OVN endpoint: %w",
			sourceObservation.err,
		)
	}
	if destinationObservation.err != nil {
		return topology.OVNPath{}, fmt.Errorf(
			"destination OVN endpoint: %w",
			destinationObservation.err,
		)
	}
	source := sourceObservation.endpoint
	destination := destinationObservation.endpoint

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
	snapshot, err := client.endpointSnapshot(ctx, logicalPort)
	if err != nil {
		return topology.OVNEndpoint{}, err
	}
	logicalPortUUID := snapshot["lsp_uuid"]
	if logicalPortUUID == "" {
		return topology.OVNEndpoint{}, fmt.Errorf(
			"%w: %s",
			ErrLogicalPortNotFound,
			logicalPort,
		)
	}

	endpoint := topology.OVNEndpoint{
		LogicalPort:     logicalPort,
		LogicalPortUUID: cleanOVSValue(logicalPortUUID),
		LogicalSwitch: referenceDisplayName(
			snapshot["logical_switch"],
		),
		PortBindingUUID: cleanOVSValue(snapshot["binding_uuid"]),
	}
	if endpoint.PortBindingUUID == "" {
		return endpoint, nil
	}

	endpoint.DatapathUUID = cleanOVSValue(snapshot["datapath_uuid"])
	endpoint.ChassisUUID = cleanOVSValue(snapshot["chassis_uuid"])
	endpoint.ChassisName = cleanOVSValue(snapshot["chassis_name"])
	endpoint.Up, _ = strconv.ParseBool(
		cleanOVSValue(snapshot["up"]),
	)
	endpoint.PortBindingTunnel, _ = strconv.Atoi(
		cleanOVSValue(snapshot["tunnel_key"]),
	)

	return endpoint, nil
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
lsp_uuid=$(run ovn-nbctl --if-exists get Logical_Switch_Port "$port" _uuid)
logical_switch=
if [ -n "$lsp_uuid" ]; then
    logical_switch=$(run ovn-nbctl lsp-get-ls "$port")
fi
binding_uuid=$(run ovn-sbctl --bare --no-headings --columns=_uuid find Port_Binding logical_port="$port")
datapath_uuid=
chassis_uuid=
chassis_name=
up=
tunnel_key=
if [ -n "$binding_uuid" ]; then
    datapath_uuid=$(run ovn-sbctl --if-exists get Port_Binding "$binding_uuid" datapath)
    chassis_uuid=$(run ovn-sbctl --if-exists get Port_Binding "$binding_uuid" chassis)
    up=$(run ovn-sbctl --if-exists get Port_Binding "$binding_uuid" up)
    tunnel_key=$(run ovn-sbctl --if-exists get Port_Binding "$binding_uuid" tunnel_key)
    if [ -n "$chassis_uuid" ]; then
        chassis_name=$(run ovn-sbctl --if-exists get Chassis "$chassis_uuid" name)
    fi
fi
printf 'lsp_uuid=%s\nlogical_switch=%s\nbinding_uuid=%s\ndatapath_uuid=%s\nchassis_uuid=%s\nchassis_name=%s\nup=%s\ntunnel_key=%s\n' \
    "$lsp_uuid" "$logical_switch" "$binding_uuid" "$datapath_uuid" \
    "$chassis_uuid" "$chassis_name" "$up" "$tunnel_key"`

	result, err := client.runner.Run(
		ctx,
		client.config.Host,
		"sh",
		"-c",
		script,
		"pathfinder-ovn-snapshot",
		client.config.ContainerEngine,
		client.config.Container,
		logicalPort,
	)
	if err != nil {
		return nil, fmt.Errorf("OVN endpoint snapshot: %w", err)
	}
	return parseSnapshot(result.Stdout), nil
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

func referenceDisplayName(value string) string {
	value = cleanOVSValue(value)
	open := strings.Index(value, "(")
	if open < 0 || !strings.HasSuffix(value, ")") {
		return value
	}
	name := strings.TrimSpace(value[open+1 : len(value)-1])
	if name == "" {
		return strings.TrimSpace(value[:open])
	}
	return name
}
