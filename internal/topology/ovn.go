package topology

type OVNEndpoint struct {
	LogicalPort       string
	LogicalPortUUID   string
	LogicalSwitch     string
	PortBindingUUID   string
	DatapathUUID      string
	ChassisUUID       string
	ChassisName       string
	Up                bool
	PortBindingTunnel int
}

type OVNPath struct {
	Source      OVNEndpoint
	Destination OVNEndpoint
	Microflow   string
	Trace       string
}
