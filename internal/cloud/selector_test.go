package cloud

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const testServerID = "11111111-1111-1111-1111-111111111111"
const secondServerID = "22222222-2222-2222-2222-222222222222"
const testPortID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const secondPortID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

type fakeSelectorBackend struct {
	ports       []selectorPort
	servers     []selectorServer
	portError   error
	serverError error
	portCalls   []portSelectorFilter
	serverCalls []string
}

func (backend *fakeSelectorBackend) ListPorts(
	_ context.Context,
	filter portSelectorFilter,
) ([]selectorPort, error) {
	backend.portCalls = append(backend.portCalls, filter)
	return append([]selectorPort(nil), backend.ports...), backend.portError
}

func (backend *fakeSelectorBackend) ListServers(
	_ context.Context,
	name string,
) ([]selectorServer, error) {
	backend.serverCalls = append(backend.serverCalls, name)
	return append([]selectorServer(nil), backend.servers...),
		backend.serverError
}

func TestEndpointSelectorRetainsBarePortUUID(t *testing.T) {
	t.Parallel()

	backend := &fakeSelectorBackend{}
	resolver := newEndpointSelectorResolver(backend)
	resolved, err := resolver.Resolve(context.Background(), testPortID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != testPortID {
		t.Fatalf("resolved = %q, want %q", resolved, testPortID)
	}
	if len(backend.portCalls) != 0 || len(backend.serverCalls) != 0 {
		t.Fatalf(
			"bare UUID queried APIs: ports=%v servers=%v",
			backend.portCalls,
			backend.serverCalls,
		)
	}
}

func TestEndpointSelectorResolvesUniqueNeutronPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
	}{
		{name: "IP", selector: "ip:192.0.2.10"},
		{name: "port name", selector: "port:web"},
		{name: "VM ID", selector: "vm-id:" + testServerID},
		{name: "VM name", selector: "vm:web-vm"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			backend := &fakeSelectorBackend{
				ports: []selectorPort{{
					ID:          testPortID,
					Name:        "web",
					NetworkID:   "network-a",
					DeviceID:    testServerID,
					DeviceOwner: "compute:nova",
					FixedIPs:    []string{"192.0.2.10"},
				}},
				servers: []selectorServer{{
					ID:   testServerID,
					Name: "web-vm",
				}},
			}
			resolver := newEndpointSelectorResolver(backend)
			resolved, err := resolver.Resolve(
				context.Background(),
				test.selector,
			)
			if err != nil {
				t.Fatal(err)
			}
			if resolved != testPortID {
				t.Fatalf(
					"Resolve(%q) = %q, want %q",
					test.selector,
					resolved,
					testPortID,
				)
			}
		})
	}
}

func TestEndpointSelectorRejectsAmbiguousPortMatches(t *testing.T) {
	t.Parallel()

	backend := &fakeSelectorBackend{
		ports: []selectorPort{
			{
				ID:        testPortID,
				Name:      "shared",
				NetworkID: "network-a",
				FixedIPs:  []string{"192.0.2.10"},
			},
			{
				ID:        secondPortID,
				Name:      "shared",
				NetworkID: "network-b",
				FixedIPs:  []string{"192.0.2.10"},
			},
		},
	}
	resolver := newEndpointSelectorResolver(backend)
	for _, selector := range []string{"ip:192.0.2.10", "port:shared"} {
		_, err := resolver.Resolve(context.Background(), selector)
		if !errors.Is(err, ErrEndpointSelectorAmbiguous) {
			t.Fatalf("Resolve(%q) error = %v", selector, err)
		}
		var ambiguous *AmbiguousEndpointSelectorError
		if !errors.As(err, &ambiguous) {
			t.Fatalf("Resolve(%q) error type = %T", selector, err)
		}
		if len(ambiguous.Candidates) != 2 ||
			!strings.Contains(err.Error(), testPortID) ||
			!strings.Contains(err.Error(), secondPortID) {
			t.Fatalf(
				"Resolve(%q) candidates = %v",
				selector,
				ambiguous.Candidates,
			)
		}
	}
}

func TestEndpointSelectorRequiresIPForMultiNICVM(t *testing.T) {
	t.Parallel()

	backend := &fakeSelectorBackend{
		ports: []selectorPort{
			{
				ID:          testPortID,
				DeviceID:    testServerID,
				DeviceOwner: "compute:nova",
				FixedIPs:    []string{"192.0.2.10"},
			},
			{
				ID:          secondPortID,
				DeviceID:    testServerID,
				DeviceOwner: "compute:nova",
				FixedIPs:    []string{"198.51.100.10"},
			},
		},
		servers: []selectorServer{{
			ID:   testServerID,
			Name: "router-vm",
		}},
	}
	resolver := newEndpointSelectorResolver(backend)

	for _, selector := range []string{
		"vm-id:" + testServerID,
		"vm:router-vm",
	} {
		_, err := resolver.Resolve(context.Background(), selector)
		if !errors.Is(err, ErrEndpointSelectorAmbiguous) {
			t.Fatalf("Resolve(%q) error = %v", selector, err)
		}
		if !strings.Contains(err.Error(), "@IP") {
			t.Fatalf("Resolve(%q) lacks @IP hint: %v", selector, err)
		}
	}

	tests := []string{
		"vm-id:" + testServerID + "@198.51.100.10",
		"vm:router-vm@198.51.100.10",
	}
	for _, selector := range tests {
		resolved, err := resolver.Resolve(context.Background(), selector)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", selector, err)
		}
		if resolved != secondPortID {
			t.Fatalf(
				"Resolve(%q) = %q, want %q",
				selector,
				resolved,
				secondPortID,
			)
		}
	}
}

func TestEndpointSelectorNeverChoosesArbitraryDuplicateVMName(t *testing.T) {
	t.Parallel()

	backend := &fakeSelectorBackend{
		servers: []selectorServer{
			{ID: testServerID, Name: "duplicate"},
			{ID: secondServerID, Name: "duplicate"},
		},
		ports: []selectorPort{
			{
				ID:          testPortID,
				DeviceID:    testServerID,
				DeviceOwner: "compute:nova",
				FixedIPs:    []string{"192.0.2.10"},
			},
			{
				ID:          secondPortID,
				DeviceID:    secondServerID,
				DeviceOwner: "compute:nova",
				FixedIPs:    []string{"198.51.100.10"},
			},
		},
	}
	resolver := newEndpointSelectorResolver(backend)

	_, err := resolver.Resolve(context.Background(), "vm:duplicate")
	if !errors.Is(err, ErrEndpointSelectorAmbiguous) {
		t.Fatalf("duplicate VM name error = %v", err)
	}
	if !strings.Contains(err.Error(), "vm-id:"+testServerID) ||
		!strings.Contains(err.Error(), "vm-id:"+secondServerID) {
		t.Fatalf("duplicate VM candidates missing: %v", err)
	}

	resolved, err := resolver.Resolve(
		context.Background(),
		"vm:duplicate@198.51.100.10",
	)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != secondPortID {
		t.Fatalf("resolved = %q, want %q", resolved, secondPortID)
	}
}

func TestEndpointSelectorReportsInvalidAndMissingSelectors(t *testing.T) {
	t.Parallel()

	resolver := newEndpointSelectorResolver(&fakeSelectorBackend{})
	for _, selector := range []string{
		"",
		"web",
		"port:",
		"ip:not-an-ip",
		"vm-id:not-a-uuid",
		"unknown:value",
	} {
		if _, err := resolver.Resolve(
			context.Background(),
			selector,
		); err == nil {
			t.Fatalf("Resolve(%q) succeeded", selector)
		}
	}

	_, err := resolver.Resolve(context.Background(), "port:missing")
	if !errors.Is(err, ErrEndpointSelectorNotFound) {
		t.Fatalf("missing selector error = %v", err)
	}
}

func TestEndpointSelectorPropagatesBackendErrors(t *testing.T) {
	t.Parallel()

	portFailure := errors.New("neutron unavailable")
	resolver := newEndpointSelectorResolver(&fakeSelectorBackend{
		portError: portFailure,
	})
	_, err := resolver.Resolve(context.Background(), "port:web")
	if !errors.Is(err, portFailure) {
		t.Fatalf("Neutron error = %v", err)
	}

	serverFailure := errors.New("nova unavailable")
	resolver = newEndpointSelectorResolver(&fakeSelectorBackend{
		serverError: serverFailure,
	})
	_, err = resolver.Resolve(context.Background(), "vm:web")
	if !errors.Is(err, serverFailure) {
		t.Fatalf("Nova error = %v", err)
	}
}
