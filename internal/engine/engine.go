package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"pathfinder/internal/cloud"
	"pathfinder/internal/diagnose"
	"pathfinder/internal/execx"
	"pathfinder/internal/ovn"
	"pathfinder/internal/ovs"
	"pathfinder/internal/probe"
	"pathfinder/internal/topology"
)

type Options struct {
	SourcePortID      string
	DestinationPortID string
	Microflow         string
	ConnectionStates  []string
	Minimal           bool
	PlanOnly          bool
	ProbeTimeout      time.Duration

	OVNHost           string
	EnableOVS         bool
	HostMappings      map[string]string
	ContainerEngine   string
	OVNContainer      string
	OVSContainer      string
	IntegrationBridge string
	SSH               execx.SSHConfig
	Runner            execx.Runner
}

type Timings struct {
	Neutron time.Duration
	OVN     time.Duration
	OVS     time.Duration
	Probe   time.Duration
	Total   time.Duration
}

type Result struct {
	Neutron topology.NeutronPath

	OVN          *topology.OVNPath
	OVNRequested bool
	OVNError     error

	OVS          *topology.OVSPath
	OVSRequested bool
	OVSError     error

	Probe          *topology.ProbeResult
	ProbeRequested bool
	ProbeError     error

	Diagnosis diagnose.Report
	Timings   Timings
}

func Analyze(ctx context.Context, options Options) (Result, error) {
	started := time.Now()
	result := Result{
		OVNRequested:   options.OVNHost != "",
		OVSRequested:   options.EnableOVS,
		ProbeRequested: !options.PlanOnly,
	}

	neutronStarted := time.Now()
	networkClient, err := cloud.NewNetworkClient(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("create Neutron client: %w", err)
	}
	result.Neutron, err = cloud.DiscoverNeutronPath(
		ctx,
		networkClient,
		options.SourcePortID,
		options.DestinationPortID,
	)
	result.Timings.Neutron = time.Since(neutronStarted)
	if err != nil {
		return Result{}, err
	}

	runner := options.Runner
	if runner == nil {
		runner = execx.SystemRunner{SSH: options.SSH}
	}

	var waitGroup sync.WaitGroup
	var ovnObservation observation[topology.OVNPath]
	var ovsObservation observation[topology.OVSPath]

	if result.OVNRequested {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ovnObservation = analyzeOVN(
				ctx,
				runner,
				result.Neutron,
				options,
			)
		}()
	}
	if result.OVSRequested {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ovsObservation = analyzeOVS(
				ctx,
				runner,
				result.Neutron,
				options,
			)
		}()
	}
	waitGroup.Wait()

	if result.OVNRequested {
		result.OVN = ovnObservation.value
		result.OVNError = ovnObservation.err
		result.Timings.OVN = ovnObservation.duration
	}
	if result.OVSRequested {
		result.OVS = ovsObservation.value
		result.OVSError = ovsObservation.err
		result.Timings.OVS = ovsObservation.duration
	}
	if result.ProbeRequested {
		probeObservation := analyzeProbe(
			ctx,
			runner,
			result.Neutron,
			result.OVS,
			options,
		)
		result.Probe = probeObservation.value
		result.ProbeError = probeObservation.err
		result.Timings.Probe = probeObservation.duration
	}

	result.Diagnosis = diagnose.Build(diagnose.Input{
		Neutron:        result.Neutron,
		OVN:            result.OVN,
		OVNRequested:   result.OVNRequested,
		OVNError:       result.OVNError,
		OVS:            result.OVS,
		OVSRequested:   result.OVSRequested,
		OVSError:       result.OVSError,
		Probe:          result.Probe,
		ProbeRequested: result.ProbeRequested,
		ProbeError:     result.ProbeError,
		Microflow:      options.Microflow,
	})
	result.Timings.Total = time.Since(started)
	return result, nil
}

func analyzeProbe(
	ctx context.Context,
	runner execx.Runner,
	path topology.NeutronPath,
	ovsPath *topology.OVSPath,
	options Options,
) observation[topology.ProbeResult] {
	started := time.Now()
	result := observation[topology.ProbeResult]{}
	if ovsPath == nil {
		result.err = fmt.Errorf(
			"live probe requires successful OVS discovery",
		)
		result.duration = time.Since(started)
		return result
	}

	sourceClient, destinationClient, err := ovsClients(
		runner,
		path,
		options,
	)
	if err != nil {
		result.err = err
		result.duration = time.Since(started)
		return result
	}
	probeResult, err := probe.Run(
		ctx,
		sourceClient,
		destinationClient,
		path,
		*ovsPath,
		options.Microflow,
		options.ProbeTimeout,
	)
	result.duration = time.Since(started)
	if err != nil {
		result.err = fmt.Errorf("run live probe: %w", err)
		return result
	}
	result.value = &probeResult
	return result
}

type observation[T any] struct {
	value    *T
	err      error
	duration time.Duration
}

func analyzeOVN(
	ctx context.Context,
	runner execx.Runner,
	path topology.NeutronPath,
	options Options,
) observation[topology.OVNPath] {
	started := time.Now()
	client := ovn.NewClient(
		runner,
		ovn.Config{
			Host:            options.OVNHost,
			ContainerEngine: options.ContainerEngine,
			Container:       options.OVNContainer,
		},
	)
	pathResult, err := client.DiscoverPath(
		ctx,
		path,
		options.Microflow,
		options.ConnectionStates,
		options.Minimal,
	)
	observationResult := observation[topology.OVNPath]{
		duration: time.Since(started),
	}
	if err != nil {
		observationResult.err = fmt.Errorf("discover OVN path: %w", err)
		return observationResult
	}
	observationResult.value = &pathResult
	return observationResult
}

func analyzeOVS(
	ctx context.Context,
	runner execx.Runner,
	path topology.NeutronPath,
	options Options,
) observation[topology.OVSPath] {
	started := time.Now()
	observationResult := observation[topology.OVSPath]{}
	sourceClient, destinationClient, err := ovsClients(
		runner,
		path,
		options,
	)
	if err != nil {
		observationResult.err = err
		observationResult.duration = time.Since(started)
		return observationResult
	}
	pathResult, err := ovs.DiscoverPath(
		ctx,
		sourceClient,
		destinationClient,
		path,
		options.Microflow,
	)
	observationResult.duration = time.Since(started)
	if err != nil {
		observationResult.err = fmt.Errorf("discover OVS path: %w", err)
		return observationResult
	}
	observationResult.value = &pathResult
	return observationResult
}

func ovsClients(
	runner execx.Runner,
	path topology.NeutronPath,
	options Options,
) (*ovs.Client, *ovs.Client, error) {
	sourceHost := execx.ResolveHost(
		path.Source.Endpoint.HostID,
		options.HostMappings,
	)
	destinationHost := execx.ResolveHost(
		path.Destination.Endpoint.HostID,
		options.HostMappings,
	)
	if sourceHost == "" || destinationHost == "" {
		return nil, nil, fmt.Errorf(
			"OVS operation requires both Neutron ports to have a host binding",
		)
	}
	sourceClient := ovs.NewClient(
		runner,
		ovs.Config{
			Host:            sourceHost,
			ContainerEngine: options.ContainerEngine,
			Container:       options.OVSContainer,
			Bridge:          options.IntegrationBridge,
		},
	)
	destinationClient := ovs.NewClient(
		runner,
		ovs.Config{
			Host:            destinationHost,
			ContainerEngine: options.ContainerEngine,
			Container:       options.OVSContainer,
			Bridge:          options.IntegrationBridge,
		},
	)
	return sourceClient, destinationClient, nil
}
