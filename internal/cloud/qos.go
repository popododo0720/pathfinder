package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/qos/policies"
)

func GetQoSPolicy(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.QoSPolicy, error) {
	policy, err := policies.Get(ctx, client, id).Extract()
	if err != nil {
		return topology.QoSPolicy{}, err
	}

	rules := make([]map[string]any, len(policy.Rules))
	for index, rule := range policy.Rules {
		rules[index] = make(map[string]any, len(rule))
		for key, value := range rule {
			rules[index][key] = value
		}
	}

	return topology.QoSPolicy{
		ID:          policy.ID,
		ProjectID:   policy.ProjectID,
		Name:        policy.Name,
		Description: policy.Description,
		Shared:      policy.Shared,
		IsDefault:   policy.IsDefault,
		Rules:       rules,
	}, nil
}
