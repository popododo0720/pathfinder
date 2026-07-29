package ovn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"pathfinder/internal/execx"
	"pathfinder/internal/topology"
)

type fakeRunner struct {
	responses map[string]string
	commands  []string
	mu        sync.Mutex
}

func (runner *fakeRunner) Run(
	_ context.Context,
	host string,
	name string,
	args ...string,
) (execx.Result, error) {
	command := host + "|" + name + "|" + strings.Join(args, " ")
	runner.mu.Lock()
	runner.commands = append(runner.commands, command)
	runner.mu.Unlock()

	for match, response := range runner.responses {
		if strings.Contains(command, match) {
			return execx.Result{Stdout: response}, nil
		}
	}

	return execx.Result{}, fmt.Errorf(
		"unexpected command: %s",
		command,
	)
}

func TestGetEndpoint(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: map[string]string{
			"central|sh|-c": "lsp_uuid=lsp-uuid\n" +
				"logical_switch=switch-uuid (neutron-network)\n" +
				"binding_uuid=binding-uuid\n" +
				"datapath_uuid=datapath-uuid\n" +
				"chassis_uuid=chassis-uuid\n" +
				"chassis_name=\"stack2\"\n" +
				"up=true\n" +
				"tunnel_key=42\n",
		},
	}
	client := NewClient(runner, Config{
		Host:            "central",
		ContainerEngine: "docker",
		Container:       "ovn_northd",
	})

	endpoint, err := client.GetEndpoint(
		context.Background(),
		"port-id",
	)
	if err != nil {
		t.Fatal(err)
	}

	if endpoint.LogicalPortUUID != "lsp-uuid" {
		t.Errorf(
			"LogicalPortUUID = %q",
			endpoint.LogicalPortUUID,
		)
	}
	if endpoint.LogicalSwitch != "neutron-network" {
		t.Errorf("LogicalSwitch = %q", endpoint.LogicalSwitch)
	}
	if endpoint.DatapathUUID != "datapath-uuid" {
		t.Errorf("DatapathUUID = %q", endpoint.DatapathUUID)
	}
	if endpoint.ChassisName != "stack2" {
		t.Errorf("ChassisName = %q", endpoint.ChassisName)
	}
	if !endpoint.Up {
		t.Error("Up = false, want true")
	}
	if endpoint.PortBindingTunnel != 42 {
		t.Errorf(
			"PortBindingTunnel = %d",
			endpoint.PortBindingTunnel,
		)
	}
}

func TestGetEndpointPropagatesContainerCommandFailure(t *testing.T) {
	t.Parallel()

	client := NewClient(execx.SystemRunner{}, Config{
		ContainerEngine: "/bin/false",
		Container:       "missing-container",
	})

	_, err := client.GetEndpoint(context.Background(), "port-id")
	if err == nil {
		t.Fatal("GetEndpoint() succeeded when the container command failed")
	}
	if errors.Is(err, ErrLogicalPortNotFound) {
		t.Fatalf("container failure was masked as a missing logical port: %v", err)
	}
	var commandError *execx.CommandError
	if !errors.As(err, &commandError) {
		t.Fatalf("GetEndpoint() error does not contain CommandError: %v", err)
	}
}

func TestGetEndpointReportsMissingLogicalPort(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: map[string]string{
		"central|sh|-c": "",
	}}
	client := NewClient(runner, Config{
		Host:      "central",
		Container: "ovn_northd",
	})

	_, err := client.GetEndpoint(context.Background(), "missing-port")
	if !errors.Is(err, ErrLogicalPortNotFound) {
		t.Fatalf("GetEndpoint() error = %v", err)
	}
}

func TestSummaryTracePreservesConnectionStateOrder(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: map[string]string{
		"ovn-trace --summary --ct trk,new --ct trk,est switch flow": "summary",
	}}
	client := NewClient(runner, Config{
		Host:      "central",
		Container: "ovn_northd",
	})

	trace, err := client.SummaryTrace(
		context.Background(),
		"switch",
		"flow",
		[]string{"trk,new", "trk,est"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if trace != "summary" {
		t.Fatalf("trace = %q, want summary", trace)
	}
}

func TestDiscoverPathKeepsDetailedTraceWhenSummaryFails(t *testing.T) {
	t.Parallel()

	runner := &summaryFailureRunner{}
	client := NewClient(runner, Config{
		Host:      "central",
		Container: "ovn_northd",
	})
	neutronPath := topology.NeutronPath{
		Source: endpointContext(
			"source-port",
			"fa:16:3e:00:00:01",
			"network",
			"192.0.2.10",
		),
		Destination: endpointContext(
			"destination-port",
			"fa:16:3e:00:00:02",
			"network",
			"192.0.2.20",
		),
	}

	path, err := client.DiscoverPath(
		context.Background(),
		neutronPath,
		"icmp",
		[]string{"trk,est"},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if path.Trace != "detailed trace" {
		t.Fatalf("detailed trace = %q", path.Trace)
	}
	if path.SummaryTrace != "" {
		t.Fatalf("summary trace = %q, want empty fallback", path.SummaryTrace)
	}
}

type summaryFailureRunner struct{}

func (*summaryFailureRunner) Run(
	_ context.Context,
	_ string,
	name string,
	args ...string,
) (execx.Result, error) {
	if name == "sh" {
		port := args[len(args)-1]
		return execx.Result{
			Stdout: "lsp_uuid=" + port + "-uuid\n" +
				"logical_switch=network\n" +
				"binding_uuid=" + port + "-binding\n" +
				"datapath_uuid=datapath\n" +
				"up=true\n",
		}, nil
	}
	command := strings.Join(args, " ")
	if strings.Contains(command, "--summary") {
		return execx.Result{}, errors.New("summary unsupported")
	}
	if strings.Contains(command, "ovn-trace") {
		return execx.Result{Stdout: "detailed trace"}, nil
	}
	return execx.Result{}, fmt.Errorf("unexpected command: %s %s", name, command)
}
