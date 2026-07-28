package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
)

func GetSecurityGroup(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.SecurityGroup, error) {
	group, err := groups.Get(ctx, client, id).Extract()
	if err != nil {
		return topology.SecurityGroup{}, err
	}

	securityRules := make([]topology.SecurityRule, len(group.Rules))
	for index, rule := range group.Rules {
		securityRules[index] = topology.SecurityRule{
			ID:                   rule.ID,
			Direction:            rule.Direction,
			EtherType:            rule.EtherType,
			Protocol:             rule.Protocol,
			PortRangeMin:         rule.PortRangeMin,
			PortRangeMax:         rule.PortRangeMax,
			RemoteIPPrefix:       rule.RemoteIPPrefix,
			RemoteGroupID:        rule.RemoteGroupID,
			RemoteAddressGroupID: rule.RemoteAddressGroupID,
			Description:          rule.Description,
		}
	}

	return topology.SecurityGroup{
		ID:          group.ID,
		ProjectID:   group.ProjectID,
		Name:        group.Name,
		Description: group.Description,
		Stateful:    group.Stateful,
		Rules:       securityRules,
	}, nil
}
