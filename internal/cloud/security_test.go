package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
)

func TestGetSecurityGroupPreservesNullAndZeroICMPFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/security-groups/group-id" {
				t.Errorf("request path = %q", request.URL.Path)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{
				"security_group": {
					"id": "group-id",
					"project_id": "project-id",
					"name": "default",
					"stateful": true,
					"security_group_rules": [
						{
							"id": "any-icmp",
							"direction": "ingress",
							"ethertype": "IPv4",
							"protocol": "icmp",
							"port_range_min": null,
							"port_range_max": null
						},
						{
							"id": "echo-reply",
							"direction": "ingress",
							"ethertype": "IPv4",
							"protocol": "1",
							"port_range_min": 0,
							"port_range_max": 0
						}
					]
				}
			}`))
		},
	))
	t.Cleanup(server.Close)

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       server.URL + "/",
	}
	group, err := GetSecurityGroup(
		context.Background(),
		client,
		"group-id",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(group.Rules))
	}
	if group.Rules[0].PortRangeMinSet ||
		group.Rules[0].PortRangeMaxSet {
		t.Fatalf("null ICMP fields became set: %+v", group.Rules[0])
	}
	if !group.Rules[1].PortRangeMinSet ||
		!group.Rules[1].PortRangeMaxSet {
		t.Fatalf("zero ICMP fields became unset: %+v", group.Rules[1])
	}
	if group.Rules[1].PortRangeMin != 0 ||
		group.Rules[1].PortRangeMax != 0 {
		t.Fatalf("zero ICMP fields changed: %+v", group.Rules[1])
	}
}
