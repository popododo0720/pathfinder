package topology

type FixedIP struct {
	Address  string
	SubnetID string
}

type EndpointSelection struct {
	PortID    string
	IPAddress string
}

type Endpoint struct {
	PortID           string
	ProjectID        string
	Name             string
	Status           string
	MACAddress       string
	NetworkID        string
	DeviceID         string
	DeviceOwner      string
	HostID           string
	VIFType          string
	VNICType         string
	QoSPolicyID      string
	SecurityGroupIDs []string
	// PortSecurityEnabled is nil when Neutron did not return the
	// port_security_enabled extension field.
	PortSecurityEnabled *bool
	FixedIPs            []FixedIP
}

func (endpoint Endpoint) SameNetwork(other Endpoint) bool {
	return endpoint.NetworkID != "" && endpoint.NetworkID == other.NetworkID
}
