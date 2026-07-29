package engine

import (
	"context"
	"fmt"
)

type endpointSelectorResolver interface {
	Resolve(context.Context, string) (string, error)
}

func resolveEndpointSelectors(
	ctx context.Context,
	resolver endpointSelectorResolver,
	source string,
	destination string,
) (string, string, error) {
	sourcePortID, err := resolver.Resolve(ctx, source)
	if err != nil {
		return "", "", fmt.Errorf(
			"resolve source endpoint %q: %w",
			source,
			err,
		)
	}
	destinationPortID, err := resolver.Resolve(ctx, destination)
	if err != nil {
		return "", "", fmt.Errorf(
			"resolve destination endpoint %q: %w",
			destination,
			err,
		)
	}
	return sourcePortID, destinationPortID, nil
}
