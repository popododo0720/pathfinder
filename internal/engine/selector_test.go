package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeEndpointResolver struct {
	values map[string]string
	errFor map[string]error
	calls  []string
}

func (resolver *fakeEndpointResolver) Resolve(
	_ context.Context,
	selector string,
) (string, error) {
	resolver.calls = append(resolver.calls, selector)
	if err := resolver.errFor[selector]; err != nil {
		return "", err
	}
	return resolver.values[selector], nil
}

func TestResolveEndpointSelectorsResolvesBeforeDiscovery(t *testing.T) {
	t.Parallel()

	resolver := &fakeEndpointResolver{
		values: map[string]string{
			"vm:web":       "source-port-id",
			"ip:192.0.2.2": "destination-port-id",
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
	if source != "source-port-id" ||
		destination != "destination-port-id" {
		t.Fatalf("resolved = %q -> %q", source, destination)
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
		values: map[string]string{"source": "source-port-id"},
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
