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

func TestTraceWithSummaryUsesSingleDetailedInvocation(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: map[string]string{
		"ovn-trace --detailed --summary --ct trk,new --ct trk,est switch flow": `# tcp
# Detailed trace.
detailed trace
# Summary trace.
summary trace`,
	}}
	client := NewClient(runner, Config{
		Host:      "central",
		Container: "ovn_northd",
	})

	trace, summary, err := client.TraceWithSummary(
		context.Background(),
		"switch",
		"flow",
		[]string{"trk,new", "trk,est"},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if trace != "# tcp\ndetailed trace" {
		t.Fatalf("trace = %q", trace)
	}
	if summary != "# tcp\nsummary trace" {
		t.Fatalf("summary = %q", summary)
	}
	if len(runner.commands) != 1 {
		t.Fatalf(
			"ovn-trace command count = %d, want 1: %v",
			len(runner.commands),
			runner.commands,
		)
	}
}

func TestTraceWithSummarySelectsMinimalSection(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: map[string]string{
		"ovn-trace --summary --minimal --ct trk,est switch flow": "# udp\r\n" +
			"  # Summary trace.  \r\nsummary trace\r\n" +
			"# Minimal trace.\r\nminimal trace\r\n",
	}}
	client := NewClient(runner, Config{
		Host:      "central",
		Container: "ovn_northd",
	})

	trace, summary, err := client.TraceWithSummary(
		context.Background(),
		"switch",
		"flow",
		[]string{"trk,est"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if trace != "# udp\nminimal trace" {
		t.Fatalf("trace = %q", trace)
	}
	if summary != "# udp\nsummary trace" {
		t.Fatalf("summary = %q", summary)
	}
	if len(runner.commands) != 1 {
		t.Fatalf(
			"ovn-trace command count = %d, want 1: %v",
			len(runner.commands),
			runner.commands,
		)
	}
}

func TestSplitTraceOutputFallsBackWithoutExpectedBanners(t *testing.T) {
	t.Parallel()

	const output = "# flow\nlegacy detailed trace"
	trace, summary := splitTraceOutput(output, false)
	if trace != output {
		t.Fatalf("trace = %q, want full output %q", trace, output)
	}
	if summary != "" {
		t.Fatalf("summary = %q, want empty fallback", summary)
	}
}

func TestDiscoverPathUsesOneTraceAndFallsBackWithoutBanners(
	t *testing.T,
) {
	t.Parallel()

	runner := &fakeRunner{responses: map[string]string{
		"central|sh|-c": "lsp_uuid=lsp-uuid\n" +
			"logical_switch=network\n" +
			"binding_uuid=binding-uuid\n" +
			"datapath_uuid=datapath\n" +
			"up=true\n",
		"ovn-trace --detailed --summary": "legacy detailed trace",
	}}
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
	if path.Trace != "legacy detailed trace" {
		t.Fatalf("detailed trace = %q", path.Trace)
	}
	if path.SummaryTrace != "" {
		t.Fatalf("summary trace = %q, want empty fallback", path.SummaryTrace)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	traceCommands := 0
	for _, command := range runner.commands {
		if strings.Contains(command, "ovn-trace") {
			traceCommands++
		}
	}
	if traceCommands != 1 {
		t.Fatalf(
			"ovn-trace command count = %d, want 1: %v",
			traceCommands,
			runner.commands,
		)
	}
}
