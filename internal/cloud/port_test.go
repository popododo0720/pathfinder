package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
)

func TestGetEndpointPreservesDisabledPortSecurity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/ports/port-id" {
				t.Errorf("request path = %q", request.URL.Path)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{
				"port": {
					"id": "port-id",
					"network_id": "network-id",
					"binding:host_id": "stack2",
					"binding:vif_type": "ovs",
					"binding:vnic_type": "normal",
					"qos_policy_id": "qos-id",
					"port_security_enabled": false,
					"fixed_ips": [],
					"security_groups": []
				}
			}`))
		},
	))
	t.Cleanup(server.Close)

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       server.URL + "/",
	}
	endpoint, err := GetEndpoint(context.Background(), client, "port-id")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.PortSecurityEnabled == nil {
		t.Fatal("PortSecurityEnabled = nil, want explicit false")
	}
	if *endpoint.PortSecurityEnabled {
		t.Fatal("PortSecurityEnabled = true, want false")
	}
	if endpoint.HostID != "stack2" ||
		endpoint.VIFType != "ovs" ||
		endpoint.VNICType != "normal" ||
		endpoint.QoSPolicyID != "qos-id" {
		t.Fatalf("port extensions were not preserved: %+v", endpoint)
	}
}

func TestGetEndpointKeepsMissingPortSecurityUnknown(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{
				"port": {
					"id": "port-id",
					"network_id": "network-id",
					"fixed_ips": [],
					"security_groups": []
				}
			}`))
		},
	))
	t.Cleanup(server.Close)

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       server.URL + "/",
	}
	endpoint, err := GetEndpoint(context.Background(), client, "port-id")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.PortSecurityEnabled != nil {
		t.Fatalf(
			"PortSecurityEnabled = %v, want unknown",
			*endpoint.PortSecurityEnabled,
		)
	}
}
