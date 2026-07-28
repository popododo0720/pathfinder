package ovn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"pathfinder/internal/execx"
)

type fakeRunner struct {
	responses map[string]string
	commands  []string
}

func (runner *fakeRunner) Run(
	_ context.Context,
	host string,
	name string,
	args ...string,
) (execx.Result, error) {
	command := host + "|" + name + "|" + strings.Join(args, " ")
	runner.commands = append(runner.commands, command)

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
			"ovn-nbctl --if-exists get Logical_Switch_Port port-id _uuid":                           "lsp-uuid\n",
			"ovn-nbctl lsp-get-ls port-id":                                                          "neutron-network\n",
			"ovn-sbctl --bare --no-headings --columns=_uuid find Port_Binding logical_port=port-id": "binding-uuid\n",
			"ovn-sbctl --if-exists get Port_Binding binding-uuid datapath":                          "datapath-uuid\n",
			"ovn-sbctl --if-exists get Port_Binding binding-uuid chassis":                           "chassis-uuid\n",
			"ovn-sbctl --if-exists get Port_Binding binding-uuid up":                                "true\n",
			"ovn-sbctl --if-exists get Port_Binding binding-uuid tunnel_key":                        "42\n",
			"ovn-sbctl --if-exists get Chassis chassis-uuid name":                                   "\"stack2\"\n",
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
