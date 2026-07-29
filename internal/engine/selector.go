package engine

import (
	"context"
	"fmt"

	"pathfinder/internal/topology"
)

type endpointSelectorResolver interface {
	Resolve(
		context.Context,
		string,
	) (topology.EndpointSelection, error)
}

func resolveEndpointSelectors(
	ctx context.Context,
	resolver endpointSelectorResolver,
	source string,
	destination string,
) (topology.EndpointSelection, topology.EndpointSelection, error) {
	sourceSelection, err := resolver.Resolve(ctx, source)
	if err != nil {
		return topology.EndpointSelection{},
			topology.EndpointSelection{},
			fmt.Errorf(
				"resolve source endpoint %q: %w",
				source,
				err,
			)
	}
	destinationSelection, err := resolver.Resolve(ctx, destination)
	if err != nil {
		return topology.EndpointSelection{},
			topology.EndpointSelection{},
			fmt.Errorf(
				"resolve destination endpoint %q: %w",
				destination,
				err,
			)
	}
	return sourceSelection, destinationSelection, nil
}
