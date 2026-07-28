package ovs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"pathfinder/internal/execx"
)

type fakeRunner struct {
	responses map[string]string
}

type captureRunner struct {
	result execx.Result
	err    error
	args   []string
}

func (runner *captureRunner) Run(
	_ context.Context,
	_ string,
	_ string,
	args ...string,
) (execx.Result, error) {
	runner.args = append([]string(nil), args...)
	return runner.result, runner.err
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

func TestCapturePacketReturnsExactMatch(t *testing.T) {
	t.Parallel()

	runner := &captureRunner{
		result: execx.Result{Stdout: "matched packet\n"},
	}
	client := NewClient(runner, Config{Host: "stack2"})
	filter := "icmp and icmp[4:2] = 42"
	result, err := client.CapturePacket(
		context.Background(),
		"tap123",
		filter,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.TimedOut || result.Output != "matched packet" {
		t.Fatalf("CapturePacket result = %+v", result)
	}
	if runner.args[len(runner.args)-1] != filter {
		t.Fatalf("capture filter args = %v", runner.args)
	}
}

func TestCapturePacketRecognizesTimeout(t *testing.T) {
	t.Parallel()

	timeoutError := &execx.CommandError{
		ExitCode: 124,
		Err:      errors.New("exit status 124"),
	}
	runner := &captureRunner{err: timeoutError}
	client := NewClient(runner, Config{Host: "stack2"})
	result, err := client.CapturePacket(
		context.Background(),
		"tap123",
		"icmp",
		100*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Fatalf("CapturePacket result = %+v", result)
	}
}
