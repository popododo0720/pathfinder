package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

var ErrEndpointSelectorNotFound = errors.New("endpoint selector not found")
var ErrEndpointSelectorAmbiguous = errors.New("endpoint selector is ambiguous")

type AmbiguousEndpointSelectorError struct {
	Selector   string
	Candidates []string
	Hint       string
}

func (err *AmbiguousEndpointSelectorError) Error() string {
	message := fmt.Sprintf(
		"%v %q; candidates: %s",
		ErrEndpointSelectorAmbiguous,
		err.Selector,
		strings.Join(err.Candidates, ", "),
	)
	if err.Hint != "" {
		message += "; " + err.Hint
	}
	return message
}

func (err *AmbiguousEndpointSelectorError) Unwrap() error {
	return ErrEndpointSelectorAmbiguous
}

type selectorPort struct {
	ID          string
	Name        string
	NetworkID   string
	DeviceID    string
	DeviceOwner string
	FixedIPs    []string
}

type selectorServer struct {
	ID   string
	Name string
}

type portSelectorFilter struct {
	Name     string
	IP       string
	DeviceID string
}

type endpointSelectorBackend interface {
	ListPorts(
		context.Context,
		portSelectorFilter,
	) ([]selectorPort, error)
	ListServers(context.Context, string) ([]selectorServer, error)
}

type EndpointSelectorResolver struct {
	backend endpointSelectorBackend
}

func NewEndpointSelectorResolver(
	networkClient *gophercloud.ServiceClient,
) *EndpointSelectorResolver {
	return &EndpointSelectorResolver{
		backend: &gophercloudSelectorBackend{
			networkClient: networkClient,
		},
	}
}

func newEndpointSelectorResolver(
	backend endpointSelectorBackend,
) *EndpointSelectorResolver {
	return &EndpointSelectorResolver{backend: backend}
}

func (resolver *EndpointSelectorResolver) Resolve(
	ctx context.Context,
	selector string,
) (topology.EndpointSelection, error) {
	selector = strings.TrimSpace(selector)
	if isUUID(selector) {
		return topology.EndpointSelection{PortID: selector}, nil
	}

	kind, value, found := strings.Cut(selector, ":")
	if !found || value == "" {
		return topology.EndpointSelection{}, invalidSelector(selector)
	}
	switch kind {
	case "ip":
		return resolver.resolveIP(ctx, selector, value)
	case "port":
		return resolver.resolvePortName(ctx, selector, value)
	case "vm-id":
		return resolver.resolveVMID(ctx, selector, value)
	case "vm":
		return resolver.resolveVMName(ctx, selector, value)
	default:
		return topology.EndpointSelection{}, invalidSelector(selector)
	}
}

func (resolver *EndpointSelectorResolver) resolveIP(
	ctx context.Context,
	selector string,
	value string,
) (topology.EndpointSelection, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return topology.EndpointSelection{}, fmt.Errorf(
			"invalid IP endpoint selector %q: %w",
			selector,
			err,
		)
	}
	candidates, err := resolver.backend.ListPorts(
		ctx,
		portSelectorFilter{IP: address.String()},
	)
	if err != nil {
		return topology.EndpointSelection{}, fmt.Errorf(
			"resolve %q: list Neutron ports: %w",
			selector,
			err,
		)
	}
	candidates = filterPorts(candidates, func(port selectorPort) bool {
		return portHasIP(port, address.String())
	})
	return selectPort(selector, candidates, "", address.String())
}

func (resolver *EndpointSelectorResolver) resolvePortName(
	ctx context.Context,
	selector string,
	name string,
) (topology.EndpointSelection, error) {
	candidates, err := resolver.backend.ListPorts(
		ctx,
		portSelectorFilter{Name: name},
	)
	if err != nil {
		return topology.EndpointSelection{}, fmt.Errorf(
			"resolve %q: list Neutron ports: %w",
			selector,
			err,
		)
	}
	candidates = filterPorts(candidates, func(port selectorPort) bool {
		return port.Name == name
	})
	return selectPort(selector, candidates, "", "")
}

func (resolver *EndpointSelectorResolver) resolveVMID(
	ctx context.Context,
	selector string,
	value string,
) (topology.EndpointSelection, error) {
	serverID, address, err := parseVMTarget(selector, value, true)
	if err != nil {
		return topology.EndpointSelection{}, err
	}
	candidates, err := resolver.vmPorts(ctx, selector, serverID)
	if err != nil {
		return topology.EndpointSelection{}, err
	}
	if address != "" {
		candidates = filterPorts(candidates, func(port selectorPort) bool {
			return portHasIP(port, address)
		})
	}
	hint := ""
	if address == "" {
		hint = fmt.Sprintf(
			"use vm-id:%s@IP to select a VM interface",
			serverID,
		)
	}
	return selectPort(selector, candidates, hint, address)
}

func (resolver *EndpointSelectorResolver) resolveVMName(
	ctx context.Context,
	selector string,
	value string,
) (topology.EndpointSelection, error) {
	name, address, err := parseVMTarget(selector, value, false)
	if err != nil {
		return topology.EndpointSelection{}, err
	}
	candidates, err := resolver.backend.ListServers(ctx, name)
	if err != nil {
		return topology.EndpointSelection{}, fmt.Errorf(
			"resolve %q: list Nova servers: %w",
			selector,
			err,
		)
	}
	candidates = filterServers(candidates, name)
	if len(candidates) == 0 {
		return topology.EndpointSelection{}, fmt.Errorf(
			"%w: %q matched no Nova server named %q",
			ErrEndpointSelectorNotFound,
			selector,
			name,
		)
	}
	if len(candidates) > 1 && address == "" {
		return topology.EndpointSelection{},
			ambiguousServers(selector, candidates)
	}

	var matchedPorts []selectorPort
	for _, server := range candidates {
		serverPorts, err := resolver.vmPorts(ctx, selector, server.ID)
		if err != nil {
			return topology.EndpointSelection{}, err
		}
		if address != "" {
			serverPorts = filterPorts(
				serverPorts,
				func(port selectorPort) bool {
					return portHasIP(port, address)
				},
			)
		}
		matchedPorts = append(matchedPorts, serverPorts...)
	}
	hint := ""
	if address == "" {
		hint = fmt.Sprintf(
			"use vm:%s@IP to select a VM interface",
			name,
		)
	}
	return selectPort(selector, matchedPorts, hint, address)
}

func (resolver *EndpointSelectorResolver) vmPorts(
	ctx context.Context,
	selector string,
	serverID string,
) ([]selectorPort, error) {
	candidates, err := resolver.backend.ListPorts(
		ctx,
		portSelectorFilter{DeviceID: serverID},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve %q: list Neutron ports for VM %s: %w",
			selector,
			serverID,
			err,
		)
	}
	return filterPorts(candidates, func(port selectorPort) bool {
		return port.DeviceID == serverID &&
			strings.HasPrefix(port.DeviceOwner, "compute:")
	}), nil
}

func parseVMTarget(
	selector string,
	value string,
	requireUUID bool,
) (string, string, error) {
	target := value
	address := ""
	if before, after, found := strings.Cut(value, "@"); found {
		if before == "" || after == "" || strings.Contains(after, "@") {
			return "", "", invalidSelector(selector)
		}
		parsed, err := netip.ParseAddr(after)
		if err != nil {
			return "", "", fmt.Errorf(
				"invalid VM interface IP in selector %q: %w",
				selector,
				err,
			)
		}
		target = before
		address = parsed.String()
	}
	if target == "" || requireUUID && !isUUID(target) {
		return "", "", invalidSelector(selector)
	}
	return target, address, nil
}

func selectPort(
	selector string,
	candidates []selectorPort,
	hint string,
	selectedIP string,
) (topology.EndpointSelection, error) {
	candidates = uniquePorts(candidates)
	switch len(candidates) {
	case 0:
		return topology.EndpointSelection{}, fmt.Errorf(
			"%w: %q matched no Neutron port",
			ErrEndpointSelectorNotFound,
			selector,
		)
	case 1:
		return topology.EndpointSelection{
			PortID:    candidates[0].ID,
			IPAddress: selectedIP,
		}, nil
	default:
		descriptions := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			descriptions = append(
				descriptions,
				describePort(candidate),
			)
		}
		sort.Strings(descriptions)
		if hint == "" {
			hint = "use a bare Neutron port UUID from the candidates"
		}
		return topology.EndpointSelection{}, &AmbiguousEndpointSelectorError{
			Selector:   selector,
			Candidates: descriptions,
			Hint:       hint,
		}
	}
}

func ambiguousServers(
	selector string,
	candidates []selectorServer,
) error {
	descriptions := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		descriptions = append(
			descriptions,
			fmt.Sprintf(
				"vm-id:%s name=%q",
				candidate.ID,
				candidate.Name,
			),
		)
	}
	sort.Strings(descriptions)
	return &AmbiguousEndpointSelectorError{
		Selector:   selector,
		Candidates: descriptions,
		Hint:       "use vm-id:UUID or vm:NAME@IP to disambiguate",
	}
}

func describePort(port selectorPort) string {
	name := "-"
	if port.Name != "" {
		name = port.Name
	}
	ips := "-"
	if len(port.FixedIPs) > 0 {
		values := append([]string(nil), port.FixedIPs...)
		sort.Strings(values)
		ips = strings.Join(values, "|")
	}
	deviceID := "-"
	if port.DeviceID != "" {
		deviceID = port.DeviceID
	}
	return fmt.Sprintf(
		"port-id=%s name=%q ips=%s network=%s vm-id=%s",
		port.ID,
		name,
		ips,
		port.NetworkID,
		deviceID,
	)
}

func uniquePorts(values []selectorPort) []selectorPort {
	byID := make(map[string]selectorPort, len(values))
	for _, value := range values {
		if value.ID != "" {
			byID[value.ID] = value
		}
	}
	result := make([]selectorPort, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ID < result[right].ID
	})
	return result
}

func filterPorts(
	values []selectorPort,
	matches func(selectorPort) bool,
) []selectorPort {
	result := make([]selectorPort, 0, len(values))
	for _, value := range values {
		if matches(value) {
			result = append(result, value)
		}
	}
	return result
}

func filterServers(
	values []selectorServer,
	name string,
) []selectorServer {
	result := make([]selectorServer, 0, len(values))
	for _, value := range values {
		if value.Name == name {
			result = append(result, value)
		}
	}
	return result
}

func portHasIP(port selectorPort, expected string) bool {
	expectedAddress, err := netip.ParseAddr(expected)
	if err != nil {
		return false
	}
	for _, address := range port.FixedIPs {
		candidateAddress, err := netip.ParseAddr(address)
		if err == nil && candidateAddress == expectedAddress {
			return true
		}
	}
	return false
}

func invalidSelector(selector string) error {
	return fmt.Errorf(
		"invalid endpoint selector %q; use a Neutron port UUID or "+
			"ip:ADDR, port:NAME, vm-id:UUID[@IP], or vm:NAME[@IP]",
		selector,
	)
}

func isUUID(value string) bool {
	const uuidLength = 36
	if len(value) != uuidLength {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			digit := character >= '0' && character <= '9'
			lowerHex := character >= 'a' && character <= 'f'
			upperHex := character >= 'A' && character <= 'F'
			if !digit && !lowerHex && !upperHex {
				return false
			}
		}
	}
	return true
}

type gophercloudSelectorBackend struct {
	networkClient *gophercloud.ServiceClient
	computeClient *gophercloud.ServiceClient
}

func (backend *gophercloudSelectorBackend) ListPorts(
	ctx context.Context,
	filter portSelectorFilter,
) ([]selectorPort, error) {
	listOptions := ports.ListOpts{
		Name:     filter.Name,
		DeviceID: filter.DeviceID,
	}
	if filter.IP != "" {
		listOptions.FixedIPs = []ports.FixedIPOpts{
			{IPAddress: filter.IP},
		}
	}
	pages, err := ports.List(
		backend.networkClient,
		listOptions,
	).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	values, err := ports.ExtractPorts(pages)
	if err != nil {
		return nil, err
	}
	result := make([]selectorPort, 0, len(values))
	for _, value := range values {
		fixedIPs := make([]string, 0, len(value.FixedIPs))
		for _, fixedIP := range value.FixedIPs {
			fixedIPs = append(fixedIPs, fixedIP.IPAddress)
		}
		result = append(result, selectorPort{
			ID:          value.ID,
			Name:        value.Name,
			NetworkID:   value.NetworkID,
			DeviceID:    value.DeviceID,
			DeviceOwner: value.DeviceOwner,
			FixedIPs:    fixedIPs,
		})
	}
	return result, nil
}

func (backend *gophercloudSelectorBackend) ListServers(
	ctx context.Context,
	name string,
) ([]selectorServer, error) {
	client, err := backend.novaClient()
	if err != nil {
		return nil, err
	}
	pages, err := servers.List(
		client,
		servers.ListOpts{Name: name},
	).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	values, err := servers.ExtractServers(pages)
	if err != nil {
		return nil, err
	}
	result := make([]selectorServer, 0, len(values))
	for _, value := range values {
		result = append(result, selectorServer{
			ID:   value.ID,
			Name: value.Name,
		})
	}
	return result, nil
}

func (backend *gophercloudSelectorBackend) novaClient() (
	*gophercloud.ServiceClient,
	error,
) {
	if backend.computeClient != nil {
		return backend.computeClient, nil
	}
	endpointOptions, err := endpointOptionsFromEnvironment()
	if err != nil {
		return nil, err
	}
	client, err := openstack.NewComputeV2(
		backend.networkClient.ProviderClient,
		endpointOptions,
	)
	if err != nil {
		return nil, err
	}
	backend.computeClient = client
	return client, nil
}
