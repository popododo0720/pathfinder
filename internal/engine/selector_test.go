package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"pathfinder/internal/topology"
)

type fakeEndpointResolver struct {
	values map[string]topology.EndpointSelection
	errFor map[string]error
	calls  []string
}

func (resolver *fakeEndpointResolver) Resolve(
	_ context.Context,
	selector string,
) (topology.EndpointSelection, error) {
	resolver.calls = append(resolver.calls, selector)
	if err := resolver.errFor[selector]; err != nil {
		return topology.EndpointSelection{}, err
	}
	return resolver.values[selector], nil
}

func TestResolveEndpointSelectorsResolvesBeforeDiscovery(t *testing.T) {
	t.Parallel()

	resolver := &fakeEndpointResolver{
		values: map[string]topology.EndpointSelection{
			"vm:web": {PortID: "source-port-id"},
			"ip:192.0.2.2": {
				PortID:    "destination-port-id",
				IPAddress: "192.0.2.2",
			},
		},
	}
	source, destination, err := resolveEndpointSelectors(
		context.Background(),
		resolver,
		"vm:web",
		"ip:192.0.2.2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if source.PortID != "source-port-id" ||
		source.IPAddress != "" ||
		destination.PortID != "destination-port-id" ||
		destination.IPAddress != "192.0.2.2" {
		t.Fatalf("resolved = %+v -> %+v", source, destination)
	}
	if len(resolver.calls) != 2 ||
		resolver.calls[0] != "vm:web" ||
		resolver.calls[1] != "ip:192.0.2.2" {
		t.Fatalf("resolver calls = %v", resolver.calls)
	}
}

func TestResolveEndpointSelectorsIdentifiesFailedRole(t *testing.T) {
	t.Parallel()

	failure := errors.New("ambiguous")
	resolver := &fakeEndpointResolver{
		values: map[string]topology.EndpointSelection{
			"source": {PortID: "source-port-id"},
		},
		errFor: map[string]error{"destination": failure},
	}
	_, _, err := resolveEndpointSelectors(
		context.Background(),
		resolver,
		"source",
		"destination",
	)
	if !errors.Is(err, failure) ||
		!strings.Contains(err.Error(), "destination endpoint") {
		t.Fatalf("error = %v", err)
	}
}
