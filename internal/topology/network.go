package topology

type Network struct {
	ID              string
	ProjectID       string
	Name            string
	Status          string
	External        bool
	MTU             int
	NetworkType     string
	PhysicalNetwork string
	SegmentationID  string
	QoSPolicyID     string
	SubnetIDs       []string
}
