package cloud

import (
	"context"
	"encoding/json"

	"pathfinder/internal/topology"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/portsbinding"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/qos/policies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

type neutronPort struct {
	ports.Port
	portsbinding.PortsBindingExt
	policies.QoSPolicyExt
	PortSecurityEnabled *bool `json:"port_security_enabled"`
}

func (port *neutronPort) UnmarshalJSON(data []byte) error {
	var base ports.Port
	if err := json.Unmarshal(data, &base); err != nil {
		return err
	}
	var binding portsbinding.PortsBindingExt
	if err := json.Unmarshal(data, &binding); err != nil {
		return err
	}
	var qos policies.QoSPolicyExt
	if err := json.Unmarshal(data, &qos); err != nil {
		return err
	}
	var security struct {
		PortSecurityEnabled *bool `json:"port_security_enabled"`
	}
	if err := json.Unmarshal(data, &security); err != nil {
		return err
	}
	port.Port = base
	port.PortsBindingExt = binding
	port.QoSPolicyExt = qos
	port.PortSecurityEnabled = security.PortSecurityEnabled
	return nil
}

func getPort(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (*neutronPort, error) {
	var port neutronPort

	err := ports.Get(ctx, client, id).ExtractInto(&port)
	if err != nil {
		return nil, err
	}

	return &port, nil
}

func GetEndpoint(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	id string,
) (topology.Endpoint, error) {
	port, err := getPort(ctx, client, id)
	if err != nil {
		return topology.Endpoint{}, err
	}

	fixedIPs := make([]topology.FixedIP, len(port.FixedIPs))

	for index, fixedIP := range port.FixedIPs {
		fixedIPs[index] = topology.FixedIP{
			Address:  fixedIP.IPAddress,
			SubnetID: fixedIP.SubnetID,
		}
	}

	return topology.Endpoint{
		PortID:              port.ID,
		ProjectID:           port.ProjectID,
		Name:                port.Name,
		Status:              port.Status,
		MACAddress:          port.MACAddress,
		NetworkID:           port.NetworkID,
		DeviceID:            port.DeviceID,
		DeviceOwner:         port.DeviceOwner,
		HostID:              port.HostID,
		VIFType:             port.VIFType,
		VNICType:            port.VNICType,
		QoSPolicyID:         port.QoSPolicyID,
		SecurityGroupIDs:    append([]string(nil), port.SecurityGroups...),
		PortSecurityEnabled: port.PortSecurityEnabled,
		FixedIPs:            fixedIPs,
	}, nil
}
