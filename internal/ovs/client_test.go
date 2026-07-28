package ovs

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"pathfinder/internal/execx"
)

type fakeRunner struct {
	responses map[string]string
}

func (runner *fakeRunner) Run(
	_ context.Context,
	host string,
	name string,
	args ...string,
) (execx.Result, error) {
	command := host + "|" + name + "|" + strings.Join(args, " ")
	for match, response := range runner.responses {
		if strings.Contains(command, match) {
			return execx.Result{Stdout: response}, nil
		}
	}
	return execx.Result{}, fmt.Errorf("unexpected command: %s", command)
}

func TestGetEndpoint(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: map[string]string{
			"stack2|sh|-c": "interface=tap123\n" +
				"ofport=9\n" +
				"link_state=\"up\"\n" +
				"error=[]\n",
		},
	}
	client := NewClient(runner, Config{
		Host:      "stack2",
		Container: "openvswitch_vswitchd",
	})

	endpoint, err := client.GetEndpoint(
		context.Background(),
		"port-id",
	)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Interface != "tap123" {
		t.Errorf("Interface = %q", endpoint.Interface)
	}
	if endpoint.OFPort != 9 {
		t.Errorf("OFPort = %d", endpoint.OFPort)
	}
	if endpoint.LinkState != "up" {
		t.Errorf("LinkState = %q", endpoint.LinkState)
	}
	if endpoint.Host != "stack2" {
		t.Errorf("Host = %q", endpoint.Host)
	}
}
