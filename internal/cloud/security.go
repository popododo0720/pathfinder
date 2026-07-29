package cloud

import (
	"context"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
)

type neutronSecurityRule struct {
	ID                   string `json:"id"`
	Direction            string `json:"direction"`
	EtherType            string `json:"ethertype"`
	Protocol             string `json:"protocol"`
	PortRangeMin         *int   `json:"port_range_min"`
	PortRangeMax         *int   `json:"port_range_max"`
	RemoteIPPrefix       string `json:"remote_ip_prefix"`
	RemoteGroupID        string `json:"remote_group_id"`
	RemoteAddressGroupID string `json:"remote_address_group_id"`
	Description          string `json:"description"`
}

type neutronSecurityGroup struct {
	ID          string                `json:"id"`
	ProjectID   string                `json:"project_id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Stateful    bool                  `json:"stateful"`
	Rules       []neutronSecurityRule `json:"security_group_rules"`
}

func GetSecurityGroup(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.SecurityGroup, error) {
	var response struct {
		SecurityGroup neutronSecurityGroup `json:"security_group"`
	}
	if err := groups.Get(ctx, client, id).ExtractInto(&response); err != nil {
		return topology.SecurityGroup{}, err
	}
	group := response.SecurityGroup

	securityRules := make([]topology.SecurityRule, len(group.Rules))
	for index, rule := range group.Rules {
		securityRule := topology.SecurityRule{
			ID:                   rule.ID,
			Direction:            rule.Direction,
			EtherType:            rule.EtherType,
			Protocol:             rule.Protocol,
			PortRangeMinSet:      rule.PortRangeMin != nil,
			PortRangeMaxSet:      rule.PortRangeMax != nil,
			RemoteIPPrefix:       rule.RemoteIPPrefix,
			RemoteGroupID:        rule.RemoteGroupID,
			RemoteAddressGroupID: rule.RemoteAddressGroupID,
			Description:          rule.Description,
		}
		if rule.PortRangeMin != nil {
			securityRule.PortRangeMin = *rule.PortRangeMin
		}
		if rule.PortRangeMax != nil {
			securityRule.PortRangeMax = *rule.PortRangeMax
		}
		securityRules[index] = securityRule
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
