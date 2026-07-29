package cloud

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
)

func TestCheckNetworkReadAccessQueriesOnePortPage(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			requests++
			if request.URL.Path != "/ports" {
				t.Errorf("request path = %q", request.URL.Path)
			}
			if request.URL.Query().Get("limit") != "1" {
				t.Errorf("request limit = %q", request.URL.Query().Get("limit"))
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ports":[]}`))
		},
	))
	t.Cleanup(server.Close)

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       server.URL + "/",
	}
	if err := CheckNetworkReadAccess(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("Neutron requests = %d, want 1", requests)
	}
}

func TestCheckNetworkReadAccessReportsForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			http.Error(writer, "forbidden", http.StatusForbidden)
		},
	))
	t.Cleanup(server.Close)

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       server.URL + "/",
	}
	err := CheckNetworkReadAccess(context.Background(), client)
	if err == nil {
		t.Fatal("forbidden Neutron read was accepted")
	}
}

func TestCheckComputeEndpointUsesConfiguredSelector(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_INTERFACE", "internal")
	t.Setenv("OS_REGION_NAME", "RegionOne")

	var requested gophercloud.EndpointOpts
	provider := &gophercloud.ProviderClient{
		EndpointLocator: func(options gophercloud.EndpointOpts) (string, error) {
			requested = options
			return "https://compute.example/v2.1/", nil
		},
	}
	client := &gophercloud.ServiceClient{ProviderClient: provider}
	if err := CheckComputeEndpoint(client); err != nil {
		t.Fatal(err)
	}
	if requested.Type != "compute" ||
		requested.Region != "RegionOne" ||
		requested.Availability != gophercloud.AvailabilityInternal {
		t.Fatalf("Nova endpoint selector = %+v", requested)
	}
}

func TestCheckComputeEndpointReportsMissingCatalogEntry(t *testing.T) {
	clearOpenStackEnvironment(t)
	missing := errors.New("compute endpoint missing")
	provider := &gophercloud.ProviderClient{
		EndpointLocator: func(gophercloud.EndpointOpts) (string, error) {
			return "", missing
		},
	}
	client := &gophercloud.ServiceClient{ProviderClient: provider}
	err := CheckComputeEndpoint(client)
	if !errors.Is(err, missing) {
		t.Fatalf("Nova endpoint error = %v", err)
	}
}
