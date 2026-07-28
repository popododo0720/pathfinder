package diagnose

import "pathfinder/internal/topology"

type Status string

const (
	StatusPass    Status = "PASS"
	StatusWarning Status = "WARN"
	StatusFail    Status = "FAIL"
	StatusUnknown Status = "UNKNOWN"
)

type Hop struct {
	ID     string
	Label  string
	Status Status
	Detail string
}

type Link struct {
	From   string
	To     string
	Label  string
	Status Status
}

type Finding struct {
	Layer   string
	Status  Status
	Message string
}

type Report struct {
	Hops     []Hop
	Links    []Link
	Findings []Finding
	Verdict  Status
}

type Input struct {
	Neutron        topology.NeutronPath
	OVN            *topology.OVNPath
	OVNRequested   bool
	OVNError       error
	OVS            *topology.OVSPath
	OVSRequested   bool
	OVSError       error
	Probe          *topology.ProbeResult
	ProbeRequested bool
	ProbeError     error
	Microflow      string
}
