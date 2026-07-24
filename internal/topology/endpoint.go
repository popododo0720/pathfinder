package topology

type FixedIP struct {
	Address  string
	SubnetID string
}

type Endpoint struct {
	PortID      string
	Name        string
	Status      string
	MACAddress  string
	NetworkID   string
	DeviceID    string
	DeviceOwner string
	HostID      string
	VIFType     string
	VNICType    string
	FixedIPs    []FixedIP
}

func (endpoint Endpoint) SameNetwork(other Endpoint) bool {
	return endpoint.NetworkID != "" && endpoint.NetworkID == other.NetworkID
}
