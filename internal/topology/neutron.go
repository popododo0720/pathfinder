package topology

type HostRoute struct {
	Destination string
	NextHop     string
}

type Subnet struct {
	ID             string
	ProjectID      string
	NetworkID      string
	Name           string
	IPVersion      int
	CIDR           string
	GatewayIP      string
	EnableDHCP     bool
	DNSNameservers []string
	HostRoutes     []HostRoute
}

type RouterRoute struct {
	Destination string
	NextHop     string
}

type Router struct {
	ID                string
	ProjectID         string
	Name              string
	Status            string
	AdminStateUp      bool
	Distributed       bool
	ExternalNetworkID string
	EnableSNAT        bool
	ExternalFixedIPs  []FixedIP
	Routes            []RouterRoute
	InterfacePortIDs  []string
	InterfaceSubnets  []string
	Interfaces        []RouterInterface
}

type RouterInterface struct {
	PortID     string
	SubnetID   string
	IPAddress  string
	MACAddress string
}

type SecurityRule struct {
	ID                   string
	Direction            string
	EtherType            string
	Protocol             string
	PortRangeMin         int
	PortRangeMax         int
	RemoteIPPrefix       string
	RemoteGroupID        string
	RemoteAddressGroupID string
	Description          string
}

type SecurityGroup struct {
	ID          string
	ProjectID   string
	Name        string
	Description string
	Stateful    bool
	Rules       []SecurityRule
}

type QoSPolicy struct {
	ID          string
	ProjectID   string
	Name        string
	Description string
	Shared      bool
	IsDefault   bool
	Rules       []map[string]any
}

type FloatingIP struct {
	ID                string
	Status            string
	FloatingNetworkID string
	FloatingAddress   string
	FixedAddress      string
	PortID            string
	RouterID          string
}

type EndpointContext struct {
	Endpoint       Endpoint
	Network        Network
	Subnets        []Subnet
	SecurityGroups []SecurityGroup
	QoSPolicy      *QoSPolicy
	FloatingIPs    []FloatingIP
}

type NeutronPath struct {
	Source      EndpointContext
	Destination EndpointContext
	Routers     []Router
}
