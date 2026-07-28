package topology

type OVSEndpoint struct {
	Host        string
	Interface   string
	OFPort      int
	LinkState   string
	Error       string
	LogicalPort string
}

type OVSPath struct {
	Source      OVSEndpoint
	Destination OVSEndpoint
	Flow        string
	Trace       string
}
